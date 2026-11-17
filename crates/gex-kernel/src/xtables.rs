//! iptables' tables, as the legacy interface keeps them (`ip_tables.c`,
//! `ip6_tables.c`, `x_tables.c` at android17-6.18): what Android's netd
//! loads through `iptables-restore` and `ip6tables-restore` at its start,
//! and fails without.
//!
//! The interface is a raw socket's options: `IPT_SO_GET_INFO`,
//! `IPT_SO_GET_ENTRIES` and the revision questions read, `IPT_SO_SET_REPLACE`
//! swaps a table whole (handing back the old one's counters) and
//! `IPT_SO_SET_ADD_COUNTERS` adds to them; `IP6T_` the same for IPv6.
//! A table is a blob of entries, each an `ipt_entry` (or `ip6t_entry`), its
//! matches and a target; a replacement is checked as `translate_table`
//! checks it, entry by entry (alignment, offsets, the standard and error
//! targets, each hook's entry and underflow), every chain walked from each
//! hook (`mark_source_chains`: jumps to entry starts, no loops, and which
//! hooks reach each entry), and every match and target named found, of the
//! size the kernel's extension has, in a table and at hooks it allows.
//!
//! The rules are kept, not applied: this kernel's internet sockets are the
//! host's, and no packet passes through a hook here. Of the extensions'
//! own checks, those listed in [`ext_check`] are made; the rest are taken
//! as given (said once when used). `xt_bpf` does not look its program up.

use crate::errno::Errno;
use std::collections::HashMap;
use std::sync::Mutex;

/// The socket options (`IPT_SO_*`, `IP6T_SO_*`: the same numbers).
pub const SO_SET_REPLACE: u64 = 64;
pub const SO_SET_ADD_COUNTERS: u64 = 65;
pub const SO_GET_INFO: u64 = 64;
pub const SO_GET_ENTRIES: u64 = 65;
pub const SO_GET_REVISION_MATCH: u64 = 66;
pub const SO_GET_REVISION_TARGET: u64 = 67;
/// IPv6's revision questions (`IP6T_SO_GET_REVISION_*`) are numbered
/// apart from IPv4's.
pub const SO6_GET_REVISION_MATCH: u64 = 68;
pub const SO6_GET_REVISION_TARGET: u64 = 69;

/// The levels: `SOL_IP`, `SOL_IPV6`.
pub const SOL_IP: u64 = 0;
pub const SOL_IPV6: u64 = 41;

/// The hooks (`NF_INET_*`).
const HOOKS: usize = 5;
const PRE_ROUTING: u32 = 1 << 0;
const LOCAL_IN: u32 = 1 << 1;
const FORWARD: u32 = 1 << 2;
const LOCAL_OUT: u32 = 1 << 3;
const POST_ROUTING: u32 = 1 << 4;

/// Verdicts as a standard target holds them (`-NF_x - 1`), and `XT_RETURN`.
const NF_DROP: i32 = 0;
const NF_ACCEPT: i32 = 1;
const NF_QUEUE: i32 = 3;
const XT_RETURN: i32 = -5;

/// A match's or target's header (`xt_entry_match`, `xt_entry_target`).
const EXT_HDR: usize = 32;
const STANDARD_SIZE: usize = 40;
const ERROR_SIZE: usize = 64;
const TABLE_MAXNAMELEN: usize = 32;

/// IPv4 or IPv6: the entry's layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// `sizeof(struct ipt_entry)` / `ip6t_entry`.
    fn entry(self) -> usize {
        match self {
            Family::V4 => 112,
            Family::V6 => 168,
        }
    }
    /// The `ipt_ip` / `ip6t_ip6` part.
    fn ip(self) -> usize {
        match self {
            Family::V4 => 84,
            Family::V6 => 136,
        }
    }
    fn target_offset_at(self) -> usize {
        match self {
            Family::V4 => 88,
            Family::V6 => 140,
        }
    }
    fn comefrom_at(self) -> usize {
        self.target_offset_at() + 4
    }
    fn counters_at(self) -> usize {
        match self {
            Family::V4 => 96,
            Family::V6 => 152,
        }
    }
    /// Where the protocol, flags and inverse flags are in the ip part.
    fn proto_at(self) -> usize {
        match self {
            Family::V4 => 80,
            Family::V6 => 128,
        }
    }
    fn flags_at(self) -> usize {
        match self {
            Family::V4 => 82,
            Family::V6 => 131,
        }
    }
    fn invflags_at(self) -> usize {
        self.flags_at() + 1
    }
    /// `IPT_F_MASK` / `IP6T_F_MASK`.
    fn flags_mask(self) -> u8 {
        match self {
            Family::V4 => 0x03,
            Family::V6 => 0x07,
        }
    }
}

const INV_MASK: u8 = 0x7f;
const INV_PROTO: u8 = 0x40;

fn xt_align(n: usize) -> usize {
    n.next_multiple_of(8)
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn i32_at(b: &[u8], at: usize) -> i32 {
    u32_at(b, at) as i32
}
fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
/// A NUL-terminated name in `b` (all of it if there is no NUL).
fn name_in(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// An extension: a match or a target the kernel has.
struct Ext {
    name: &'static str,
    revision: u8,
    /// `None`: both families (`NFPROTO_UNSPEC`).
    family: Option<Family>,
    target: bool,
    /// `matchsize` / `targetsize`, unaligned.
    size: usize,
    /// What user space sees of it (`usersize`), where the rest is the
    /// kernel's own (a pointer it fills): zero to user space.
    usersize: Option<usize>,
    table: Option<&'static str>,
    hooks: u32,
    proto: u16,
}

const fn ext(name: &'static str, revision: u8, family: Option<Family>, target: bool, size: usize) -> Ext {
    Ext { name, revision, family, target, size, usersize: None, table: None, hooks: 0, proto: 0 }
}

/// The extensions android17-6.18's GKI builds that Android's networking
/// uses (`system/netd`'s rules, and libxtables' own: the standard and
/// error targets, `state` as `conntrack`), with the kernel's sizes
/// (the uapi structures, `XT_ALIGN`ed when checked) and limits.
static EXTS: &[Ext] = &[
    // The standard target (a verdict or a jump) and the error target (a
    // chain's head, and the table's end).
    ext("", 0, None, true, 4),
    ext("ERROR", 0, None, true, 30),
    // Matches.
    Ext { hooks: LOCAL_OUT | POST_ROUTING, ..ext("owner", 1, None, false, 20) },
    ext("u32", 0, None, false, 1984),
    Ext { usersize: Some(24), ..ext("quota2", 3, None, false, 32) },
    ext("connmark", 1, None, false, 12),
    ext("state", 0, None, false, 4),
    ext("conntrack", 1, None, false, 152),
    ext("conntrack", 2, None, false, 156),
    ext("conntrack", 3, None, false, 164),
    Ext { usersize: Some(520), ..ext("bpf", 0, None, false, 528) },
    Ext { usersize: Some(520), ..ext("bpf", 1, None, false, 528) },
    ext("mark", 1, None, false, 12),
    Ext { proto: 17, ..ext("udp", 0, None, false, 10) },
    Ext { proto: 6, ..ext("tcp", 0, None, false, 12) },
    Ext { proto: 1, ..ext("icmp", 0, Some(Family::V4), false, 4) },
    Ext { proto: 58, ..ext("icmp6", 0, Some(Family::V6), false, 4) },
    ext("policy", 0, None, false, 308),
    Ext { hooks: PRE_ROUTING, ..ext("rpfilter", 0, None, false, 1) },
    Ext { usersize: Some(32), ..ext("limit", 0, None, false, 40) },
    Ext { usersize: Some(16), ..ext("quota", 0, None, false, 24) },
    ext("comment", 0, None, false, 256),
    ext("multiport", 1, None, false, 48),
    ext("length", 0, None, false, 6),
    ext("iprange", 1, None, false, 68),
    // Targets.
    Ext { hooks: LOCAL_IN | FORWARD | LOCAL_OUT, ..ext("REJECT", 0, Some(Family::V4), true, 4) },
    Ext { hooks: LOCAL_IN | FORWARD | LOCAL_OUT, ..ext("REJECT", 0, Some(Family::V6), true, 4) },
    ext("CONNMARK", 1, None, true, 16),
    ext("CONNMARK", 2, None, true, 16),
    ext("NFLOG", 0, None, true, 76),
    ext("MARK", 2, None, true, 8),
    Ext { usersize: Some(32), ..ext("IDLETIMER", 0, None, true, 40) },
    Ext { usersize: Some(40), ..ext("IDLETIMER", 1, None, true, 48) },
    Ext { usersize: Some(32), table: Some("raw"), hooks: PRE_ROUTING | LOCAL_OUT, ..ext("CT", 0, None, true, 40) },
    Ext { usersize: Some(64), table: Some("raw"), hooks: PRE_ROUTING | LOCAL_OUT, ..ext("CT", 1, None, true, 72) },
    Ext { usersize: Some(64), table: Some("raw"), hooks: PRE_ROUTING | LOCAL_OUT, ..ext("CT", 2, None, true, 72) },
    Ext { proto: 6, hooks: FORWARD | LOCAL_OUT | POST_ROUTING, ..ext("TCPMSS", 0, None, true, 2) },
    Ext { table: Some("nat"), hooks: POST_ROUTING, ..ext("MASQUERADE", 0, Some(Family::V4), true, 20) },
    Ext { table: Some("nat"), hooks: POST_ROUTING, ..ext("MASQUERADE", 0, Some(Family::V6), true, 40) },
];

fn exts_named(family: Family, target: bool, name: &[u8]) -> impl Iterator<Item = &'static Ext> + '_ {
    EXTS.iter().filter(move |e| e.target == target && e.name.as_bytes() == name && e.family.is_none_or(|f| f == family))
}

/// The tables there are: name and hooks.
const TABLES: &[(&str, u32)] = &[
    ("filter", LOCAL_IN | FORWARD | LOCAL_OUT),
    ("mangle", PRE_ROUTING | LOCAL_IN | FORWARD | LOCAL_OUT | POST_ROUTING),
    ("raw", PRE_ROUTING | LOCAL_OUT),
    ("nat", PRE_ROUTING | LOCAL_IN | LOCAL_OUT | POST_ROUTING),
    ("security", LOCAL_IN | FORWARD | LOCAL_OUT),
];

/// One table as the kernel holds it (`xt_table_info`).
#[derive(Clone, Debug)]
struct Table {
    valid_hooks: u32,
    hook_entry: [u32; HOOKS],
    underflow: [u32; HOOKS],
    number: u32,
    entries: Vec<u8>,
    /// Each entry's packets and bytes, in order.
    counters: Vec<(u64, u64)>,
}

static STATE: Mutex<Option<HashMap<(Family, String), Table>>> = Mutex::new(None);

fn say_once(what: &str) {
    crate::bpf::say_once(what);
}

/// The table `name`, made as its module would make it when first asked
/// for with loading allowed (`xt_request_find_table_lock`); `ENOENT` for
/// one there is no such table, or one not yet there when loading is not
/// asked (`xt_find_table_lock`).
fn with_table<R>(family: Family, name: &str, load: bool, f: impl FnOnce(&mut Table) -> Result<R, Errno>) -> Result<R, Errno> {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let tables = g.get_or_insert_with(HashMap::new);
    let key = (family, name.to_string());
    if !tables.contains_key(&key) {
        let Some(&(_, hooks)) = TABLES.iter().find(|(n, _)| *n == name).filter(|_| load) else {
            return Err(Errno::ENOENT);
        };
        tables.insert(key.clone(), initial(family, name, hooks)?);
    }
    f(tables.get_mut(&key).unwrap())
}

/// A table as `ipt_alloc_initial_table` makes it: an accepting policy at
/// each hook, and the error entry that ends it.
fn initial(family: Family, name: &str, hooks: u32) -> Result<Table, Errno> {
    let mut blob = Vec::new();
    let (mut hook_entry, mut underflow) = ([0u32; HOOKS], [0u32; HOOKS]);
    let mut n = 0;
    for h in 0..HOOKS {
        if hooks & (1 << h) == 0 {
            continue;
        }
        hook_entry[h] = blob.len() as u32;
        underflow[h] = blob.len() as u32;
        blob.extend(entry_with(family, "", &(-NF_ACCEPT - 1).to_le_bytes(), STANDARD_SIZE));
        n += 1;
    }
    let mut err = [0u8; 30];
    err[..5].copy_from_slice(b"ERROR");
    blob.extend(entry_with(family, "ERROR", &err, ERROR_SIZE));
    n += 1;
    translate(family, name, hooks, n, &hook_entry, &underflow, blob)
}

/// An unconditional entry with no matches and the target `name`.
fn entry_with(family: Family, name: &str, data: &[u8], target_size: usize) -> Vec<u8> {
    let mut e = vec![0u8; family.entry() + target_size];
    e[family.target_offset_at()..family.target_offset_at() + 2].copy_from_slice(&(family.entry() as u16).to_le_bytes());
    e[family.target_offset_at() + 2..family.target_offset_at() + 4].copy_from_slice(&((family.entry() + target_size) as u16).to_le_bytes());
    let t = family.entry();
    e[t..t + 2].copy_from_slice(&(target_size as u16).to_le_bytes());
    e[t + 2..t + 2 + name.len()].copy_from_slice(name.as_bytes());
    e[t + EXT_HDR..t + EXT_HDR + data.len()].copy_from_slice(data);
    e
}

/// An entry's offsets, and its target's.
fn target_offset(family: Family, b: &[u8], e: usize) -> usize {
    u16_at(b, e + family.target_offset_at()) as usize
}
fn next_offset(family: Family, b: &[u8], e: usize) -> usize {
    u16_at(b, e + family.target_offset_at() + 2) as usize
}
fn target_name(family: Family, b: &[u8], e: usize) -> &[u8] {
    let t = e + target_offset(family, b, e);
    name_in(&b[t + 2..t + 31])
}

/// `unconditional`: no matches and an ip part of zeros.
fn unconditional(family: Family, b: &[u8], e: usize) -> bool {
    target_offset(family, b, e) == family.entry() && b[e..e + family.ip()].iter().all(|&x| x == 0)
}

/// `verdict_ok`.
fn verdict_ok(v: i32) -> bool {
    if v > 0 {
        return true;
    }
    if v < 0 {
        if v == XT_RETURN {
            return true;
        }
        return matches!(-v - 1, NF_ACCEPT | NF_DROP | NF_QUEUE);
    }
    false
}

/// `xt_check_entry_offsets`.
fn check_offsets(family: Family, b: &[u8], e: usize, target_offset: usize, next_offset: usize) -> Result<(), Errno> {
    if target_offset < family.entry() || target_offset + EXT_HDR > next_offset {
        return Err(Errno::EINVAL);
    }
    let t = e + target_offset;
    let tsize = u16_at(b, t) as usize;
    if tsize < EXT_HDR || target_offset + tsize > next_offset {
        return Err(Errno::EINVAL);
    }
    let name = name_in(&b[t + 2..t + 31]);
    if name.is_empty() {
        if xt_align(target_offset + 36) != next_offset || !verdict_ok(i32_at(b, t + EXT_HDR)) {
            return Err(Errno::EINVAL);
        }
    } else if name == b"ERROR" {
        // `error_tg_ok`: its size, and its name ended within it.
        if tsize != ERROR_SIZE || !b[t + EXT_HDR..t + EXT_HDR + 30].contains(&0) {
            return Err(Errno::EINVAL);
        }
    }
    // `xt_check_entry_match`: the matches fill what is before the target.
    let mut at = e + family.entry();
    let mut length = target_offset as isize - family.entry() as isize;
    while length > 0 {
        if at % 8 != 0 || length < EXT_HDR as isize {
            return Err(Errno::EINVAL);
        }
        let ms = u16_at(b, at) as usize;
        if ms < EXT_HDR || ms as isize > length {
            return Err(Errno::EINVAL);
        }
        length -= ms as isize;
        at += ms;
    }
    Ok(())
}

/// `translate_table`: a table checked, with which hooks reach each entry;
/// the error a replacement made of it would get otherwise.
fn translate(family: Family, table: &str, valid_hooks: u32, number: u32, hook_entries: &[u32; HOOKS], underflows: &[u32; HOOKS], mut b: Vec<u8>) -> Result<Table, Errno> {
    let size = b.len();
    let (mut hook_entry, mut underflow) = ([u32::MAX; HOOKS], [u32::MAX; HOOKS]);
    let mut offsets = Vec::new();
    let mut pos = 0usize;
    let mut i = 0u32;
    while pos < size {
        // `check_entry_size_and_hooks`.
        let e = pos;
        if e % 8 != 0 || e + family.entry() >= size {
            return Err(Errno::EINVAL);
        }
        let next = next_offset(family, &b, e);
        if e + next > size || next < family.entry() + EXT_HDR {
            return Err(Errno::EINVAL);
        }
        let (flags, inv) = (b[e + family.flags_at()], b[e + family.invflags_at()]);
        if flags & !family.flags_mask() != 0 || inv & !INV_MASK != 0 {
            return Err(Errno::EINVAL);
        }
        check_offsets(family, &b, e, target_offset(family, &b, e), next)?;
        for h in 0..HOOKS {
            if valid_hooks & (1 << h) == 0 {
                continue;
            }
            if e as u32 == hook_entries[h] {
                hook_entry[h] = hook_entries[h];
            }
            if e as u32 == underflows[h] {
                // `check_underflow`: an unconditional ACCEPT or DROP.
                let t = e + target_offset(family, &b, e);
                let v = -i32_at(&b, t + EXT_HDR) - 1;
                if !unconditional(family, &b, e) || !target_name(family, &b, e).is_empty() || (v != NF_DROP && v != NF_ACCEPT) {
                    return Err(Errno::EINVAL);
                }
                underflow[h] = underflows[h];
            }
        }
        b[e + family.counters_at()..e + family.counters_at() + 16].fill(0);
        put_u32(&mut b, e + family.comefrom_at(), 0);
        if i < number {
            offsets.push(e as u32);
        }
        i += 1;
        pos += next;
    }
    if i != number {
        return Err(Errno::EINVAL);
    }
    // `xt_check_table_hooks`.
    let (mut max_entry, mut max_uflow, mut check) = (0u32, 0u32, false);
    for h in 0..HOOKS {
        if valid_hooks & (1 << h) == 0 {
            continue;
        }
        if hook_entry[h] == u32::MAX || underflow[h] == u32::MAX {
            return Err(Errno::EINVAL);
        }
        if check && (max_uflow >= underflow[h] || max_entry >= hook_entry[h]) {
            return Err(Errno::EINVAL);
        }
        max_entry = hook_entry[h];
        max_uflow = underflow[h];
        check = true;
    }
    if !mark_source_chains(family, &mut b, valid_hooks, &hook_entry, &offsets) {
        return Err(Errno::ELOOP);
    }
    // `find_check_entry`, each entry's matches then its target.
    let mut pos = 0;
    while pos < size {
        check_entry(family, table, &mut b, pos)?;
        pos += next_offset(family, &b, pos);
    }
    Ok(Table { valid_hooks, hook_entry, underflow, number, counters: vec![(0, 0); number as usize], entries: b })
}

/// `mark_source_chains`: every chain walked from each hook, as the
/// kernel walks it (the counters' packet count holding the way back, the
/// `NF_INET_NUMHOOKS` bit of `comefrom` the chain being walked), leaving
/// in each entry's `comefrom` the hooks that reach it. False for a loop or
/// a jump to no entry's start.
fn mark_source_chains(family: Family, b: &mut [u8], valid_hooks: u32, hook_entry: &[u32; HOOKS], offsets: &[u32]) -> bool {
    let size = b.len();
    let pc = family.counters_at();
    let cf = family.comefrom_at();
    const WALKING: u32 = 1 << HOOKS;
    let pcnt = |b: &[u8], e: usize| u64::from_le_bytes(b[e + pc..e + pc + 8].try_into().unwrap()) as usize;
    'hooks: for hook in 0..HOOKS {
        if valid_hooks & (1 << hook) == 0 {
            continue;
        }
        let mut pos = hook_entry[hook] as usize;
        let mut e = pos;
        // The initial back pointer.
        put_u64(b, e + pc, pos as u64);
        loop {
            let t = e + target_offset(family, b, e);
            let standard = name_in(&b[t + 2..t + 31]).is_empty();
            let verdict = i32_at(b, t + EXT_HDR);
            let comefrom = u32_at(b, e + cf);
            let visited = comefrom & (1 << hook) != 0;
            if comefrom & WALKING != 0 {
                return false;
            }
            put_u32(b, e + cf, comefrom | (1 << hook) | WALKING);
            if (unconditional(family, b, e) && standard && verdict < 0) || visited {
                // A return or the end: back through the last big jump.
                loop {
                    put_u32(b, e + cf, u32_at(b, e + cf) ^ WALKING);
                    let oldpos = pos;
                    pos = pcnt(b, e);
                    put_u64(b, e + pc, 0);
                    // At the start: this hook is done.
                    if pos == oldpos {
                        continue 'hooks;
                    }
                    e = pos;
                    if oldpos != pos + next_offset(family, b, e) {
                        break;
                    }
                }
                // Then along one.
                let step = next_offset(family, b, e);
                e = pos + step;
                if pos + step >= size {
                    return false;
                }
                put_u64(b, e + pc, pos as u64);
                pos += step;
            } else {
                let newpos = if standard && verdict >= 0 {
                    // A jump: to an entry's start (`xt_find_jump_offset`).
                    if offsets.binary_search(&(verdict as u32)).is_err() {
                        return false;
                    }
                    verdict as usize
                } else {
                    // On to the next entry.
                    let n = pos + next_offset(family, b, e);
                    if n >= size {
                        return false;
                    }
                    n
                };
                e = newpos;
                put_u64(b, e + pc, pos as u64);
                pos = newpos;
            }
        }
    }
    true
}

/// `find_check_entry`: each match, then the target, found by name and
/// revision and checked as `xt_check_match`/`xt_check_target` do.
fn check_entry(family: Family, table: &str, b: &mut [u8], e: usize) -> Result<(), Errno> {
    let hook_mask = u32_at(b, e + family.comefrom_at());
    let proto = u16_at(b, e + family.proto_at());
    let inv_proto = b[e + family.invflags_at()] & INV_PROTO != 0;
    let toff = target_offset(family, b, e);
    let mut at = e + family.entry();
    while at < e + toff {
        let size = u16_at(b, at) as usize;
        check_ext(family, table, b, e, at, false, hook_mask, proto, inv_proto)?;
        at += size;
    }
    check_ext(family, table, b, e, e + toff, true, hook_mask, proto, inv_proto)
}

#[allow(clippy::too_many_arguments)]
fn check_ext(family: Family, table: &str, b: &mut [u8], e: usize, at: usize, target: bool, hook_mask: u32, proto: u16, inv_proto: bool) -> Result<(), Errno> {
    let size = u16_at(b, at) as usize - EXT_HDR;
    let name = name_in(&b[at + 2..at + 31]).to_vec();
    let revision = b[at + 31];
    // `xt_find_match`/`xt_find_target`: the name there with another
    // revision is EPROTOTYPE, no such name ENOENT.
    let mut named = exts_named(family, target, &name).peekable();
    if named.peek().is_none() {
        return Err(Errno::ENOENT);
    }
    let Some(x) = named.find(|x| x.revision == revision) else { return Err(Errno::EPROTOTYPE) };
    if xt_align(x.size) != size {
        return Err(Errno::EINVAL);
    }
    if x.table.is_some_and(|t| t != table) {
        return Err(Errno::EINVAL);
    }
    if x.hooks != 0 && hook_mask & !x.hooks & ((1 << HOOKS) - 1) != 0 {
        return Err(Errno::EINVAL);
    }
    if x.proto != 0 && (x.proto != proto || inv_proto) {
        return Err(Errno::EINVAL);
    }
    let data = at + EXT_HDR;
    ext_check(family, table, x, b, e, data, hook_mask, proto, inv_proto)?;
    // What is the kernel's own in it reads as zeros.
    if let Some(u) = x.usersize {
        b[data + u..data + size].fill(0);
    }
    Ok(())
}

/// The extensions' own `checkentry`s, where they refuse something.
#[allow(clippy::too_many_arguments)]
fn ext_check(family: Family, table: &str, x: &Ext, b: &[u8], e: usize, d: usize, hook_mask: u32, proto: u16, inv_proto: bool) -> Result<(), Errno> {
    let _ = family;
    match (x.target, x.name) {
        // `rpfilter_check`: in the raw or mangle table only.
        (false, "rpfilter") => {
            if table != "raw" && table != "mangle" {
                return Err(Errno::EINVAL);
            }
            // XT_RPFILTER_OPTION_MASK.
            if b[d] & !0x0f != 0 {
                return Err(Errno::EINVAL);
            }
        }
        // `owner_check`: the flags it knows.
        (false, "owner") => {
            // XT_OWNER_UID | GID | SOCKET | SUPPL_GROUPS.
            let (m, inv) = (u32_at(b, d + 16) as u8, b[d + 17]);
            let _ = inv;
            if m & !0x0f != 0 {
                return Err(Errno::EINVAL);
            }
        }
        // `quota_mt2_check`: the flags, and the name ended.
        (false, "quota2") => {
            // XT_QUOTA_INVERT | GROW | PACKET | NO_CHANGE.
            if b[d + 15] & !0x0f != 0 || !b[d..d + 15].contains(&0) {
                return Err(Errno::EINVAL);
            }
        }
        // `nflog_tg_check`: the flags, and the prefix ended.
        (true, "NFLOG") => {
            // len u32, group u16, threshold u16, flags u16, pad u16, prefix[64].
            if u16_at(b, d + 8) & !0x1 != 0 || !b[d + 12..d + 76].contains(&0) {
                return Err(Errno::EINVAL);
            }
        }
        // `idletimer_tg_checkentry`: a label, ended, and a timeout.
        (true, "IDLETIMER") => {
            let timeout = u32_at(b, d);
            let label = &b[d + 4..d + 32];
            if timeout == 0 || timeout >= i32::MAX as u32 / 1000 || label[0] == 0 || !label.contains(&0) {
                return Err(Errno::EINVAL);
            }
            say_once("IDLETIMER's sysfs file for its label (xt_idletimer)");
        }
        // `tcpmss_tg4_check`: with a match on SYN.
        (true, "TCPMSS") => {
            const CLAMP_PMTU: u16 = 0xffff;
            if u16_at(b, d) == CLAMP_PMTU && hook_mask & !(FORWARD | LOCAL_OUT | POST_ROUTING) != 0 {
                return Err(Errno::EINVAL);
            }
            let mut at = e + family.entry();
            let end = e + target_offset(family, b, e);
            let mut syn = false;
            while at < end {
                if name_in(&b[at + 2..at + 31]) == b"tcp" {
                    let m = at + EXT_HDR;
                    // flg_cmp & TCPHDR_SYN, flags not inverted.
                    syn |= b[m + 10] & 0x02 != 0 && b[m + 11] & 0x04 == 0;
                }
                at += u16_at(b, at) as usize;
            }
            if !syn {
                return Err(Errno::EINVAL);
            }
        }
        // `reject_tg_check`: no echo reply, a reset only for TCP.
        (true, "REJECT") => {
            let with = u32_at(b, d);
            // `IPT_ICMP_ECHOREPLY`, `IPT_TCP_RESET`; `IP6T_ICMP6_ECHOREPLY`,
            // `IP6T_TCP_RESET`.
            let (echo_reply, tcp_reset) = match family {
                Family::V4 => (4, 7),
                Family::V6 => (5, 6),
            };
            if with == echo_reply {
                return Err(Errno::EINVAL);
            }
            if with == tcp_reset && (proto != 6 || inv_proto) {
                return Err(Errno::EINVAL);
            }
        }
        // `bpf_mt_check_v1`: its program is not looked up here.
        (false, "bpf") => say_once("xt_bpf's program (not looked up: rules are not applied)"),
        _ => {}
    }
    Ok(())
}

/// A table's name from the first 32 bytes, as the kernel ends it.
fn table_name(b: &[u8]) -> String {
    let mut n = [0u8; TABLE_MAXNAMELEN];
    n.copy_from_slice(&b[..TABLE_MAXNAMELEN]);
    n[TABLE_MAXNAMELEN - 1] = 0;
    String::from_utf8_lossy(name_in(&n)).into_owned()
}

/// `do_ipt_get_ctl` / `do_ip6t_get_ctl`: `len` the caller's buffer's
/// length, `buf` its contents (read whole first); what to write back and
/// the call's result.
pub fn get(family: Family, admin: bool, opt: u64, buf: &[u8], len: usize) -> Result<(Vec<u8>, u64), Errno> {
    if !admin {
        return Err(Errno::EPERM);
    }
    // IPv6's revision questions by IPv4's numbers (66 and 67 are no
    // option of IPv6's).
    let opt = match (family, opt) {
        (Family::V6, SO6_GET_REVISION_MATCH) => SO_GET_REVISION_MATCH,
        (Family::V6, SO6_GET_REVISION_TARGET) => SO_GET_REVISION_TARGET,
        (Family::V6, SO_GET_REVISION_MATCH | SO_GET_REVISION_TARGET) => return Err(Errno::EINVAL),
        _ => opt,
    };
    match opt {
        SO_GET_INFO => {
            if len != 84 {
                return Err(Errno::EINVAL);
            }
            let name = table_name(buf);
            with_table(family, &name, true, |t| {
                let mut out = vec![0u8; 84];
                out[..name.len()].copy_from_slice(name.as_bytes());
                put_u32(&mut out, 32, t.valid_hooks);
                for h in 0..HOOKS {
                    put_u32(&mut out, 36 + 4 * h, t.hook_entry[h]);
                    put_u32(&mut out, 56 + 4 * h, t.underflow[h]);
                }
                put_u32(&mut out, 76, t.number);
                put_u32(&mut out, 80, t.entries.len() as u32);
                Ok((out, 0))
            })
        }
        SO_GET_ENTRIES => {
            if len < 40 {
                return Err(Errno::EINVAL);
            }
            let size = u32_at(buf, 32) as usize;
            if len != 40 + size {
                return Err(Errno::EINVAL);
            }
            let name = table_name(buf);
            with_table(family, &name, false, |t| {
                if size != t.entries.len() {
                    return Err(Errno::EAGAIN);
                }
                let mut out = buf[..40].to_vec();
                let mut entries = t.entries.clone();
                let mut pos = 0;
                let mut i = 0;
                while pos < entries.len() {
                    let (p, c) = t.counters[i];
                    put_u64(&mut entries, pos + family.counters_at(), p);
                    put_u64(&mut entries, pos + family.counters_at() + 8, c);
                    pos += next_offset(family, &entries, pos);
                    i += 1;
                }
                out.extend(entries);
                Ok((out, 0))
            })
        }
        SO_GET_REVISION_MATCH | SO_GET_REVISION_TARGET => {
            if len != 30 {
                return Err(Errno::EINVAL);
            }
            let mut n = buf[..29].to_vec();
            n[28] = 0;
            let name = name_in(&n).to_vec();
            let want = buf[29];
            // `xt_find_revision`: the best revision there is, and EPROTONOSUPPORT
            // when the one asked for is not one of them.
            let mut best: i32 = -1;
            let mut have = false;
            for x in exts_named(family, opt == SO_GET_REVISION_TARGET, &name) {
                best = best.max(x.revision as i32);
                have |= x.revision == want;
            }
            if best < 0 {
                return Err(Errno::ENOENT);
            }
            if !have {
                return Err(Errno::EPROTONOSUPPORT);
            }
            Ok((buf[..30].to_vec(), best as u64))
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `do_ipt_set_ctl` / `do_ip6t_set_ctl`: `read(at, n)` reads the caller's
/// value; for a replacement, the old counters are written back through
/// `write`.
pub fn set(
    family: Family,
    admin: bool,
    opt: u64,
    len: usize,
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>, Errno>,
    write: &mut dyn FnMut(u64, &[u8]) -> Result<(), Errno>,
) -> Result<u64, Errno> {
    if !admin {
        return Err(Errno::EPERM);
    }
    match opt {
        SO_SET_REPLACE => {
            let h = read(0, 96)?;
            let name = table_name(&h);
            let valid_hooks = u32_at(&h, 32);
            let number = u32_at(&h, 36);
            let size = u32_at(&h, 40) as usize;
            let hook_entry: [u32; HOOKS] = std::array::from_fn(|i| u32_at(&h, 44 + 4 * i));
            let underflow: [u32; HOOKS] = std::array::from_fn(|i| u32_at(&h, 64 + 4 * i));
            let num_counters = u32_at(&h, 84);
            let counters_at = u64::from_le_bytes(h[88..96].try_into().unwrap());
            if num_counters as u64 >= i32::MAX as u64 / 16 {
                return Err(Errno::ENOMEM);
            }
            if num_counters == 0 {
                return Err(Errno::EINVAL);
            }
            // `xt_alloc_table_info`: none, or more than memory allows.
            if size == 0 || size > 512 << 20 {
                return Err(Errno::ENOMEM);
            }
            let _ = len;
            let blob = read(96, size)?;
            let new = translate(family, &name, valid_hooks, number, &hook_entry, &underflow, blob)?;
            let old = with_table(family, &name, true, |t| {
                if valid_hooks != t.valid_hooks {
                    return Err(Errno::EINVAL);
                }
                if num_counters != t.number {
                    return Err(Errno::EAGAIN);
                }
                Ok(std::mem::replace(t, new))
            })?;
            let mut c = Vec::with_capacity(old.counters.len() * 16);
            for (p, b) in &old.counters {
                c.extend(p.to_le_bytes());
                c.extend(b.to_le_bytes());
            }
            // The new table is in place whatever this does
            // ("counters copy to user failed while replacing table").
            let _ = write(counters_at, &c);
            Ok(0)
        }
        SO_SET_ADD_COUNTERS => {
            if len < 40 {
                return Err(Errno::EINVAL);
            }
            let h = read(0, 40)?;
            let n = u32_at(&h, 32) as usize;
            if len - 40 != n * 16 {
                return Err(Errno::EINVAL);
            }
            let add = read(40, n * 16)?;
            let name = table_name(&h);
            with_table(family, &name, false, |t| {
                if t.number as usize != n {
                    return Err(Errno::EINVAL);
                }
                for (i, c) in t.counters.iter_mut().enumerate() {
                    c.0 = c.0.wrapping_add(u64::from_le_bytes(add[16 * i..16 * i + 8].try_into().unwrap()));
                    c.1 = c.1.wrapping_add(u64::from_le_bytes(add[16 * i + 8..16 * i + 16].try_into().unwrap()));
                }
                Ok(0)
            })
        }
        _ => Err(Errno::EINVAL),
    }
}

/// A raw internet socket (`SOCK_RAW`): here only for iptables' options;
/// it sends and receives nothing.
#[derive(Debug)]
pub struct RawSocket {
    pub family: Family,
    pub protocol: u32,
}

impl crate::vfs::FileHandle for RawSocket {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        say_once("reading a raw internet socket (it carries no packets here)");
        Err(Errno::EOPNOTSUPP)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> crate::errno::SysResult {
        say_once("writing a raw internet socket (it carries no packets here)");
        Err(Errno::EOPNOTSUPP)
    }
    fn metadata(&self) -> Result<crate::vfs::Metadata, Errno> {
        Ok(crate::vfs::Metadata { file_type: crate::vfs::FileType::Socket, size: 0, mode: 0o140777, ino: 0, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }
    fn raw_socket(&self) -> Option<(Family, u32)> {
        Some((self.family, self.protocol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The filter table as Linux 7.0 gave it on a fresh boot: an
    /// accepting policy at INPUT, FORWARD and OUTPUT and the error entry,
    /// 608 bytes; each policy reached from its own hook only.
    #[test]
    fn a_fresh_filter_table_is_linuxs() {
        let t = initial(Family::V4, "filter", LOCAL_IN | FORWARD | LOCAL_OUT).unwrap();
        assert_eq!(t.number, 4);
        assert_eq!(t.entries.len(), 3 * 152 + 176);
        // A hook the table has not is left as translate_table starts it.
        let x = u32::MAX;
        assert_eq!(&t.hook_entry, &[x, 0, 152, 304, x]);
        assert_eq!(&t.underflow, &[x, 0, 152, 304, x]);
        let cf = |e: usize| u32_at(&t.entries, e + Family::V4.comefrom_at());
        assert_eq!((cf(0), cf(152), cf(304), cf(456)), (LOCAL_IN, FORWARD, LOCAL_OUT, 0));
    }

    /// A jump into a user chain and back: the chain's entries are reached
    /// from the hook that jumps; a jump to the middle of an entry, and a
    /// loop, are refused.
    #[test]
    fn chains_are_walked_as_the_kernel_walks_them() {
        let f = Family::V4;
        let std = |v: i32| entry_with(f, "", &v.to_le_bytes(), STANDARD_SIZE);
        let mut err = [0u8; 30];
        err[..5].copy_from_slice(b"ERROR");
        let error = |n: &str| {
            let mut e = [0u8; 30];
            e[..n.len()].copy_from_slice(n.as_bytes());
            entry_with(f, "ERROR", &e, ERROR_SIZE)
        };
        // INPUT: jump to "c"; FORWARD, OUTPUT: accept; "c": return; end.
        let build = |jump: i32| {
            let mut b = Vec::new();
            b.extend(std(jump)); // 0: INPUT -> c
            b.extend(std(-NF_ACCEPT - 1)); // 152: INPUT policy
            b.extend(std(-NF_ACCEPT - 1)); // 304: FORWARD
            b.extend(std(-NF_ACCEPT - 1)); // 456: OUTPUT
            b.extend(error("c")); // 608: chain head
            b.extend(std(XT_RETURN)); // 784: c's return
            b.extend(error("ERROR")); // 936
            b
        };
        let hooks = LOCAL_IN | FORWARD | LOCAL_OUT;
        let he = [0, 0, 304, 456, 0];
        let uf = [0, 152, 304, 456, 0];
        let t = translate(f, "filter", hooks, 7, &he, &uf, build(784)).unwrap();
        assert_eq!(u32_at(&t.entries, 784 + f.comefrom_at()), LOCAL_IN);
        assert_eq!(translate(f, "filter", hooks, 7, &he, &uf, build(790)).unwrap_err(), Errno::ELOOP);
        // c jumping to itself.
        let mut b = build(784);
        b[784 + f.entry() + EXT_HDR..784 + f.entry() + EXT_HDR + 4].copy_from_slice(&784i32.to_le_bytes());
        assert_eq!(translate(f, "filter", hooks, 7, &he, &uf, b).unwrap_err(), Errno::ELOOP);
    }
}
