//! A SELinux policy in its binary form, read: what a program writes to
//! `/sys/fs/selinux/load`, as `checkpolicy` or `secilc` made it.
//!
//! The form is the kernel's (security/selinux/ss/policydb.c, `policydb_read`,
//! at android17-6.18): a header, the symbol tables (commons, classes, roles,
//! types, users, booleans, sensitivities, categories), the access vector
//! table, the conditional rules, role transitions and allows, file-name
//! transitions, the contexts of initial SIDs and of filesystems, ports and
//! nodes, the genfs contexts, range transitions, and for each type the
//! attributes it has. Versions 15 to 35 exist; a policy of one older than
//! 24 is refused here, since nothing still makes one (Android's are 30 and
//! later) and their layouts differ in ways there is nothing to test with.
//!
//! Everything read is checked as the kernel checks it: a policy that names
//! a type, role, class or category that is not there is not a policy.

use std::collections::HashMap;

/// A policy that cannot be read: what was wrong with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bad(pub String);

type Res<T> = Result<T, Bad>;

fn bad<T>(what: impl Into<String>) -> Res<T> {
    Err(Bad(what.into()))
}

pub const MAGIC: u32 = 0xf97c_ff8c;
const STRING: &[u8] = b"SE Linux";
pub const VERSION_MIN: u32 = 24;
pub const VERSION_MAX: u32 = 35;

const VERSION_FILENAME_TRANS: u32 = 25;
const VERSION_ROLETRANS: u32 = 26;
const VERSION_NEW_OBJECT_DEFAULTS: u32 = 27;
const VERSION_DEFAULT_TYPE: u32 = 28;
const VERSION_CONSTRAINT_NAMES: u32 = 29;
const VERSION_XPERMS_IOCTL: u32 = 30;
const VERSION_INFINIBAND: u32 = 31;
const VERSION_COMP_FTRANS: u32 = 33;
const VERSION_COND_XPERMS: u32 = 34;
const VERSION_NEVERAUDIT: u32 = 35;

const CONFIG_MLS: u32 = 1;
const REJECT_UNKNOWN: u32 = 2;
const ALLOW_UNKNOWN: u32 = 4;
/// Android's own, for its kernels' netlink route classes.
const ANDROID_NETLINK_GETNEIGH: u32 = 1 << 30;
const ANDROID_NETLINK_ROUTE: u32 = 1 << 31;

/// The policy capabilities by number (include/policycap_names.h): a
/// policy's [`Policy::policycaps`] has a bit for each it turns on, and
/// selinuxfs a file of each name.
pub const POLICY_CAPABILITIES: [&str; 14] = [
    "network_peer_controls",
    "open_perms",
    "extended_socket_class",
    "always_check_network",
    "cgroup_seclabel",
    "nnp_nosuid_transition",
    "genfs_seclabel_symlinks",
    "ioctl_skip_cloexec",
    "userspace_initial_context",
    "netlink_xperm",
    "netif_wildcard",
    "genfs_seclabel_wildcard",
    "functionfs_seclabel",
    "memfd_class",
];

/// How a filesystem labels its files (`SECURITY_FS_USE_*`).
pub mod fs_use {
    /// By each file's `security.selinux` attribute.
    pub const XATTR: u32 = 1;
    /// As a transition from its maker's context and the filesystem's
    /// (devpts, tmpfs).
    pub const TRANS: u32 = 2;
    /// As its maker (pipes, sockets).
    pub const TASK: u32 = 3;
    /// By `genfscon`, from its path.
    pub const GENFS: u32 = 4;
    /// Not at all.
    pub const NONE: u32 = 5;
    /// As the mount says (`context=`).
    pub const MNTPOINT: u32 = 6;
    /// By the filesystem's own labels (NFS).
    pub const NATIVE: u32 = 7;
}

/// The kernel's `match_wildcard` (lib/parser.c): whether all of `text`
/// matches `pattern`, where `*` is any run of bytes and `?` any one.
pub fn wildcard_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut s) = (0, 0);
    // Where to take up again after a `*`: in the pattern, in the text.
    let mut star: Option<(usize, usize)> = None;
    while s < text.len() {
        match pattern.get(p) {
            Some(b'?') => {
                s += 1;
                p += 1;
            }
            Some(b'*') => {
                p += 1;
                if p == pattern.len() {
                    return true;
                }
                star = Some((p, s));
            }
            c => {
                if c == Some(&text[s]) {
                    s += 1;
                    p += 1;
                } else {
                    let Some((after, from)) = star else { return false };
                    star = Some((after, from + 1));
                    s = from + 1;
                    p = after;
                }
            }
        }
    }
    if pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

/// What an access vector table entry says (`AVTAB_*`).
pub mod av {
    pub const ALLOWED: u16 = 0x0001;
    pub const AUDITALLOW: u16 = 0x0002;
    pub const AUDITDENY: u16 = 0x0004;
    pub const AV: u16 = ALLOWED | AUDITALLOW | AUDITDENY;
    pub const TRANSITION: u16 = 0x0010;
    pub const MEMBER: u16 = 0x0020;
    pub const CHANGE: u16 = 0x0040;
    pub const TYPE: u16 = TRANSITION | MEMBER | CHANGE;
    pub const XPERMS_ALLOWED: u16 = 0x0100;
    pub const XPERMS_AUDITALLOW: u16 = 0x0200;
    pub const XPERMS_DONTAUDIT: u16 = 0x0400;
    pub const XPERMS: u16 = XPERMS_ALLOWED | XPERMS_AUDITALLOW | XPERMS_DONTAUDIT;
    pub const ENABLED: u16 = 0x8000;
}

/// A set of small numbers (`struct ebitmap`): bit `n` is value `n + 1` of
/// whatever it is a set of. Sparse, as the kernel's is: a policy may say
/// its highest bit is anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Bitmap {
    /// 64 bits a word, by the word's place; none is zero.
    words: std::collections::BTreeMap<u32, u64>,
}

impl Bitmap {
    pub fn get(&self, bit: u32) -> bool {
        self.words.get(&(bit / 64)).is_some_and(|w| w >> (bit % 64) & 1 != 0)
    }

    pub fn set(&mut self, bit: u32) {
        *self.words.entry(bit / 64).or_default() |= 1 << (bit % 64);
    }

    /// The bits set, lowest first.
    pub fn bits(&self) -> impl Iterator<Item = u32> + '_ {
        self.words.iter().flat_map(|(&i, &w)| (0..64).filter(move |b| w >> b & 1 != 0).map(move |b| i * 64 + b))
    }

    pub fn count(&self) -> u32 {
        self.words.values().map(|w| w.count_ones()).sum()
    }

    /// The highest bit set, and one: 0 for an empty set.
    pub fn len(&self) -> u64 {
        self.words.iter().next_back().map_or(0, |(&i, &w)| i as u64 * 64 + 64 - w.leading_zeros() as u64)
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// The bits in both.
    pub fn and(&self, other: &Bitmap) -> Bitmap {
        let words = self.words.iter().filter_map(|(i, w)| other.words.get(i).map(|o| (*i, w & o)).filter(|(_, w)| *w != 0)).collect();
        Bitmap { words }
    }

    /// Every bit of `self` is in `other`.
    pub fn within(&self, other: &Bitmap) -> bool {
        self.words.iter().all(|(i, w)| other.words.get(i).is_some_and(|o| w & !o == 0))
    }
}

/// The policy's bytes, read in order.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// The sizes of a symbol table: how many numbers it has, and how many
    /// names. No more numbers than names, and no more names than there
    /// are bytes to hold them.
    fn table(&mut self) -> Res<(u32, u32)> {
        let (nprim, nel) = (self.u32()?, self.u32()?);
        if nprim > nel || nel as usize > self.left() / 8 {
            return bad(format!("a table of {nprim} numbers and {nel} names"));
        }
        Ok((nprim, nel))
    }

    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let end = self.at.checked_add(n).filter(|&end| end <= self.bytes.len());
        let Some(end) = end else { return bad(format!("truncated at byte {}", self.at)) };
        let got = &self.bytes[self.at..end];
        self.at = end;
        Ok(got)
    }

    fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// A name of `len` bytes (`str_read`).
    fn name(&mut self, len: u32) -> Res<String> {
        if len == 0 || len == u32::MAX {
            return bad("a name of no length");
        }
        match std::str::from_utf8(self.take(len as usize)?) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => bad("a name that is not text"),
        }
    }

    /// `ebitmap_read`: the unit (64), the highest bit, the number of
    /// units, then each unit's first bit and its bits.
    fn bitmap(&mut self) -> Res<Bitmap> {
        /// The kernel's node: six words.
        const NODE: u32 = 6 * 64;
        let (unit, high, count) = (self.u32()?, self.u32()?, self.u32()?);
        if unit != 64 {
            return bad(format!("a bitmap in units of {unit}"));
        }
        let Some(high) = high.checked_add(NODE - 1).map(|h| h - h % NODE) else { return bad("a bitmap past all numbers") };
        let mut map = Bitmap::default();
        if high == 0 {
            return Ok(map);
        }
        if count == 0 {
            return bad("a bitmap with a highest bit and no bits");
        }
        let mut last: Option<u32> = None;
        for _ in 0..count {
            let start = self.u32()?;
            if start % 64 != 0 || start > high - 64 || last.is_some_and(|l| start <= l) {
                return bad(format!("a bitmap unit at bit {start}"));
            }
            let bits = self.u64()?;
            if bits == 0 {
                return bad("an empty bitmap unit");
            }
            map.words.insert(start / 64, bits);
            last = Some(start);
        }
        // The last unit is in the last node.
        if last.is_some_and(|l| l - l % NODE + NODE != high) {
            return bad("a bitmap that ends before its highest bit");
        }
        Ok(map)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Common {
    pub name: String,
    /// Permissions by name: bit `value - 1` of an access vector.
    pub perms: HashMap<String, u32>,
}

/// One node of a constraint's expression, in reverse Polish order.
#[derive(Debug, Clone)]
pub struct ConstraintExpr {
    /// `CEXPR_NOT` 1, `AND` 2, `OR` 3, `ATTR` 4, `NAMES` 5.
    pub kind: u32,
    /// What is compared (`CEXPR_USER`, `ROLE`, `TYPE`, with `TARGET` and
    /// `XTARGET`; the MLS levels).
    pub attr: u32,
    /// How (`CEXPR_EQ` 1, `NEQ` 2, `DOM` 3, `DOMBY` 4, `INCOMP` 5).
    pub op: u32,
    pub names: Bitmap,
}

#[derive(Debug, Clone)]
pub struct Constraint {
    pub perms: u32,
    pub expr: Vec<ConstraintExpr>,
}

#[derive(Debug, Clone, Default)]
pub struct Class {
    pub name: String,
    /// The common it takes permissions from: its number.
    pub common: Option<u32>,
    /// Its own permissions by name; a common's come before them.
    pub perms: HashMap<String, u32>,
    pub nperms: u32,
    pub constraints: Vec<Constraint>,
    pub validatetrans: Vec<Constraint>,
    pub default_user: u32,
    pub default_role: u32,
    pub default_range: u32,
    pub default_type: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Role {
    pub name: String,
    pub bounds: u32,
    pub dominates: Bitmap,
    pub types: Bitmap,
}

#[derive(Debug, Clone, Default)]
pub struct Type {
    pub name: String,
    pub primary: bool,
    pub attribute: bool,
    pub bounds: u32,
}

/// A sensitivity and its categories (`struct mls_level`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Level {
    pub sens: u32,
    pub cats: Bitmap,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Range {
    pub low: Level,
    pub high: Level,
}

#[derive(Debug, Clone, Default)]
pub struct User {
    pub name: String,
    pub bounds: u32,
    pub roles: Bitmap,
    pub range: Range,
    pub default_level: Level,
}

#[derive(Debug, Clone, Default)]
pub struct Bool {
    pub name: String,
    pub state: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Sensitivity {
    pub name: String,
    pub alias: bool,
    pub level: Level,
}

#[derive(Debug, Clone, Default)]
pub struct Category {
    pub name: String,
    pub alias: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Context {
    pub user: u32,
    pub role: u32,
    pub ty: u32,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvKey {
    pub source: u16,
    pub target: u16,
    pub class: u16,
    /// One of [`av`]'s kinds, and [`av::ENABLED`] in a conditional rule
    /// whose branch is in force.
    pub specified: u16,
}

/// Extended permissions: which ioctl (or netlink message) numbers a rule
/// is about (`struct avtab_extended_perms`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xperms {
    pub specified: u8,
    pub driver: u8,
    pub perms: [u32; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvDatum {
    /// An access vector, or the type a transition gives.
    Data(u32),
    Xperms(Xperms),
}

/// An access decision (`struct av_decision`): the permissions allowed, and
/// which of them are logged when granted and when denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub allowed: u32,
    pub auditallow: u32,
    pub auditdeny: u32,
    /// `AVD_FLAGS_PERMISSIVE` 1: the source's type is permissive.
    /// `AVD_FLAGS_NEVERAUDIT` 2.
    pub flags: u32,
}

/// One node of a conditional's expression: a boolean, or an operator on
/// what went before (`COND_BOOL` 1, `NOT` 2, `OR` 3, `AND` 4, `XOR` 5,
/// `EQ` 6, `NEQ` 7).
#[derive(Debug, Clone, Copy)]
pub struct CondExpr {
    pub kind: u32,
    pub boolean: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Conditional {
    pub expr: Vec<CondExpr>,
    pub when_true: Vec<(AvKey, AvDatum)>,
    pub when_false: Vec<(AvKey, AvDatum)>,
}

#[derive(Debug, Clone)]
pub struct FilenameTrans {
    /// The source types (bit `type - 1`) that get `otype`.
    pub stypes: Bitmap,
    pub otype: u32,
}

/// A context the policy gives something by name or number (`struct
/// ocontext`).
#[derive(Debug, Clone)]
pub enum OContext {
    InitialSid { sid: u32, context: Context },
    Fs { name: String, context: [Context; 2] },
    Port { protocol: u32, low: u32, high: u32, context: Context },
    Netif { name: String, context: [Context; 2] },
    Node { addr: u32, mask: u32, context: Context },
    FsUse { behavior: u32, fstype: String, context: Context },
    Node6 { addr: [u32; 4], mask: [u32; 4], context: Context },
    IbPkey { subnet_prefix: u64, low: u32, high: u32, context: Context },
    IbEndPort { name: String, port: u32, context: Context },
}

#[derive(Debug, Clone)]
pub struct GenfsPath {
    pub path: String,
    /// The class it is for, or 0 for any.
    pub class: u32,
    pub context: Context,
}

/// A policy.
#[derive(Debug, Default)]
pub struct Policy {
    pub version: u32,
    pub mls: bool,
    pub reject_unknown: bool,
    pub allow_unknown: bool,
    /// Android's header flags: which netlink route messages its kernels
    /// take as reads.
    pub android_netlink_route: bool,
    pub android_netlink_getneigh: bool,
    pub policycaps: Bitmap,
    pub permissive: Bitmap,
    pub neveraudit: Bitmap,
    /// Each by its number less one.
    pub commons: Vec<Common>,
    pub classes: Vec<Class>,
    pub roles: Vec<Role>,
    pub types: Vec<Type>,
    pub users: Vec<User>,
    pub bools: Vec<Bool>,
    /// By name: a sensitivity's number is in its level, and an alias has
    /// another's.
    pub sensitivities: Vec<Sensitivity>,
    pub nsens: u32,
    pub categories: Vec<(u32, Category)>,
    pub ncats: u32,
    pub avtab: HashMap<AvKey, AvDatum>,
    /// Extended permission rules: several may have one key.
    pub xperms: Vec<(AvKey, Xperms)>,
    pub conditionals: Vec<Conditional>,
    /// (role, type, class) to the role it becomes.
    pub role_trans: HashMap<(u32, u32, u32), u32>,
    pub role_allow: Vec<(u32, u32)>,
    /// (target type, class, name) to who gets what.
    pub filename_trans: HashMap<(u32, u32, String), Vec<FilenameTrans>>,
    pub initial_sids: Vec<OContext>,
    pub fs: Vec<OContext>,
    pub ports: Vec<OContext>,
    pub netifs: Vec<OContext>,
    pub nodes: Vec<OContext>,
    pub fs_use: Vec<OContext>,
    pub nodes6: Vec<OContext>,
    pub ib_pkeys: Vec<OContext>,
    pub ib_end_ports: Vec<OContext>,
    /// By filesystem type, each one's paths longest first.
    pub genfs: Vec<(String, Vec<GenfsPath>)>,
    /// (source type, target type, class) to the range it gets.
    pub range_trans: HashMap<(u32, u32, u32), Range>,
    /// For each type, itself and the attributes it has (bit `number - 1`).
    pub type_attrs: Vec<Bitmap>,
    /// Bytes after the last thing read: none, in a policy a compiler made.
    pub trailing: usize,
    /// Other names for types: an alias to its type's number.
    pub type_aliases: HashMap<String, u32>,
}

/// Whether the kernel takes a class of this name for a socket's
/// (`security_is_socket_class`): the classes of its own that are named so.
fn is_socket_class(name: &str) -> bool {
    const KERNEL: &[&str] = &[
        "socket", "tcp_socket", "udp_socket", "rawip_socket", "netlink_socket", "packet_socket", "key_socket", "unix_stream_socket",
        "unix_dgram_socket", "netlink_route_socket", "netlink_tcpdiag_socket", "netlink_nflog_socket", "netlink_xfrm_socket",
        "netlink_selinux_socket", "netlink_iscsi_socket", "netlink_audit_socket", "netlink_fib_lookup_socket", "netlink_connector_socket",
        "netlink_netfilter_socket", "netlink_dnrt_socket", "netlink_kobject_uevent_socket", "netlink_generic_socket",
        "netlink_scsitransport_socket", "netlink_rdma_socket", "netlink_crypto_socket", "appletalk_socket", "tun_socket", "sctp_socket",
        "icmp_socket", "ax25_socket", "ipx_socket", "netrom_socket", "atmpvc_socket", "x25_socket", "rose_socket", "decnet_socket",
        "atmsvc_socket", "rds_socket", "irda_socket", "pppox_socket", "llc_socket", "can_socket", "tipc_socket", "bluetooth_socket",
        "iucv_socket", "rxrpc_socket", "isdn_socket", "phonet_socket", "ieee802154_socket", "caif_socket", "alg_socket", "nfc_socket",
        "vsock_socket", "kcm_socket", "qipcrtr_socket", "smc_socket", "xdp_socket", "mctp_socket",
    ];
    KERNEL.contains(&name)
}

/// Put `datum` at `value - 1`, which must be free and no more than `nprim`.
fn place<T: Default + Clone>(table: &mut Vec<Option<T>>, nprim: u32, value: u32, datum: T, what: &str) -> Res<()> {
    if value == 0 || value > nprim {
        return bad(format!("{what} number {value} of {nprim}"));
    }
    let slot = &mut table[value as usize - 1];
    if slot.is_some() {
        return bad(format!("two of {what} number {value}"));
    }
    *slot = Some(datum);
    Ok(())
}

fn filled<T>(table: Vec<Option<T>>, what: &str) -> Res<Vec<T>> {
    let n = table.len();
    let all: Vec<T> = table.into_iter().flatten().collect();
    if all.len() != n {
        return bad(format!("a {what} number with no {what}"));
    }
    Ok(all)
}

impl Policy {
    /// Read a policy from its bytes.
    pub fn read(bytes: &[u8]) -> Res<Policy> {
        let mut r = Reader { bytes, at: 0 };
        let mut p = Policy::default();
        if r.u32()? != MAGIC {
            return bad("not a policy: the magic number");
        }
        let len = r.u32()?;
        if len as usize != STRING.len() || r.take(STRING.len())? != STRING {
            return bad("not a policy: the identifying string");
        }
        p.version = r.u32()?;
        if p.version < VERSION_MIN || p.version > VERSION_MAX {
            return bad(format!("policy version {} (read here: {VERSION_MIN} to {VERSION_MAX})", p.version));
        }
        let config = r.u32()?;
        p.mls = config & CONFIG_MLS != 0;
        p.reject_unknown = config & REJECT_UNKNOWN != 0;
        p.allow_unknown = config & ALLOW_UNKNOWN != 0;
        p.android_netlink_route = config & ANDROID_NETLINK_ROUTE != 0;
        p.android_netlink_getneigh = config & ANDROID_NETLINK_GETNEIGH != 0;
        let (sym_num, ocon_num) = (r.u32()?, r.u32()?);
        let ocons = if p.version >= VERSION_INFINIBAND { 9 } else { 7 };
        if sym_num != 8 || ocon_num != ocons {
            return bad(format!("{sym_num} symbol tables and {ocon_num} context tables"));
        }
        p.policycaps = r.bitmap()?;
        p.permissive = r.bitmap()?;
        if p.version >= VERSION_NEVERAUDIT {
            p.neveraudit = r.bitmap()?;
        }

        p.read_commons(&mut r)?;
        p.read_classes(&mut r)?;
        p.read_roles(&mut r)?;
        p.read_types(&mut r)?;
        p.read_users(&mut r)?;
        p.read_bools(&mut r)?;
        p.read_sensitivities(&mut r)?;
        p.read_categories(&mut r)?;
        p.check_symbols()?;

        // The access vector table: not empty.
        let n = r.u32()?;
        if n == 0 {
            return bad("no access vector rules");
        }
        for _ in 0..n {
            let (key, datum) = p.read_av(&mut r, false)?;
            match datum {
                AvDatum::Xperms(x) => p.xperms.push((key, x)),
                datum => {
                    if p.avtab.insert(key, datum).is_some() {
                        return bad("an access vector rule twice");
                    }
                }
            }
        }
        p.read_conditionals(&mut r)?;

        for _ in 0..r.u32()? {
            let (role, ty, new) = (r.u32()?, r.u32()?, r.u32()?);
            let class = if p.version >= VERSION_ROLETRANS { r.u32()? } else { p.class_named("process").unwrap_or(0) };
            if !p.role_ok(role) || !p.type_ok(ty) || !p.class_ok(class) || !p.role_ok(new) {
                return bad("a role transition of something that is not there");
            }
            if p.role_trans.insert((role, ty, class), new).is_some() {
                return bad("a role transition twice");
            }
        }
        for _ in 0..r.u32()? {
            let (role, new) = (r.u32()?, r.u32()?);
            if !p.role_ok(role) || !p.role_ok(new) {
                return bad("a role allow of a role that is not there");
            }
            p.role_allow.push((role, new));
        }
        p.read_filename_trans(&mut r)?;

        // The process class and its transition permissions are required.
        let process = p.class_named("process").ok_or(Bad("no process class".into()))?;
        for perm in ["transition", "dyntransition"] {
            if p.perm_named(process, perm).is_none() {
                return bad(format!("no process {perm} permission"));
            }
        }

        p.read_ocontexts(&mut r, ocons)?;
        p.read_genfs(&mut r)?;
        if p.mls {
            for _ in 0..r.u32()? {
                let (source, target, class) = (r.u32()?, r.u32()?, r.u32()?);
                if !p.type_ok(source) || !p.type_ok(target) || !p.class_ok(class) {
                    return bad("a range transition of something that is not there");
                }
                let range = p.read_range(&mut r)?;
                if !p.range_ok(&range) {
                    return bad("a range transition to a range that is not one");
                }
                if p.range_trans.insert((source, target, class), range).is_some() {
                    return bad("a range transition twice");
                }
            }
        }
        for i in 0..p.types.len() as u32 {
            let mut attrs = r.bitmap()?;
            // The type itself, the degenerate case.
            attrs.set(i);
            p.type_attrs.push(attrs);
        }
        p.check_bounds()?;
        p.trailing = r.left();
        Ok(p)
    }

    // -- the symbol tables ----------------------------------------------------

    fn read_perms(r: &mut Reader<'_>, n: u32) -> Res<HashMap<String, u32>> {
        let mut perms = HashMap::new();
        for _ in 0..n {
            let (len, value) = (r.u32()?, r.u32()?);
            if value == 0 || value > 32 {
                return bad(format!("permission number {value}"));
            }
            if perms.insert(r.name(len)?, value).is_some() {
                return bad("a permission twice");
            }
        }
        Ok(perms)
    }

    fn read_commons(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let (nprim, nel) = r.table()?;
        let mut table = vec![None; nprim as usize];
        for _ in 0..nel {
            let (len, value, _nperms, nel) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
            let name = r.name(len)?;
            let perms = Self::read_perms(r, nel)?;
            place(&mut table, nprim, value, Common { name, perms }, "common")?;
        }
        self.commons = filled(table, "common")?;
        Ok(())
    }

    fn read_constraints(&self, r: &mut Reader<'_>, n: u32, allow_xtarget: bool) -> Res<Vec<Constraint>> {
        const MAX_DEPTH: i32 = 5;
        /// `CEXPR_XTARGET`: the third context, which only a validatetrans
        /// rule has.
        const XTARGET: u32 = 16;
        let mut out = Vec::new();
        for _ in 0..n {
            let (perms, nexpr) = (r.u32()?, r.u32()?);
            let mut expr = Vec::new();
            let mut depth = -1i32;
            for _ in 0..nexpr {
                let (kind, attr, op) = (r.u32()?, r.u32()?, r.u32()?);
                let mut names = Bitmap::default();
                match kind {
                    // CEXPR_NOT
                    1 if depth >= 0 => {}
                    // CEXPR_AND, CEXPR_OR
                    2 | 3 if depth >= 1 => depth -= 1,
                    // CEXPR_ATTR
                    4 if depth < MAX_DEPTH - 1 => depth += 1,
                    // CEXPR_NAMES
                    5 if depth < MAX_DEPTH - 1 && (allow_xtarget || attr & XTARGET == 0) => {
                        depth += 1;
                        names = r.bitmap()?;
                        if self.version >= VERSION_CONSTRAINT_NAMES {
                            // The names as they were written (`type_set`):
                            // two sets and flags, kept by no one.
                            r.bitmap()?;
                            r.bitmap()?;
                            r.u32()?;
                        }
                    }
                    _ => return bad("a constraint expression that is not one"),
                }
                expr.push(ConstraintExpr { kind, attr, op, names });
            }
            if depth != 0 {
                return bad("a constraint expression that does not come to one value");
            }
            out.push(Constraint { perms, expr });
        }
        Ok(out)
    }

    fn read_classes(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let (nprim, nel) = r.table()?;
        let mut table = vec![None; nprim as usize];
        for _ in 0..nel {
            let (len, len2, value, nperms, nel, ncons) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
            let mut class = Class { name: r.name(len)?, nperms, ..Class::default() };
            if len2 != 0 {
                let common = r.name(len2)?;
                let at = self.commons.iter().position(|c| c.name == common);
                class.common = Some(at.ok_or(Bad(format!("class {} of unknown common {common}", class.name)))? as u32 + 1);
            }
            class.perms = Self::read_perms(r, nel)?;
            class.constraints = self.read_constraints(r, ncons, false)?;
            let n = r.u32()?;
            class.validatetrans = self.read_constraints(r, n, true)?;
            if self.version >= VERSION_NEW_OBJECT_DEFAULTS {
                (class.default_user, class.default_role, class.default_range) = (r.u32()?, r.u32()?, r.u32()?);
            }
            if self.version >= VERSION_DEFAULT_TYPE {
                class.default_type = r.u32()?;
            }
            place(&mut table, nprim, value, class, "class")?;
        }
        self.classes = filled(table, "class")?;
        Ok(())
    }

    fn read_roles(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let (nprim, nel) = r.table()?;
        let mut table = vec![None; nprim as usize];
        for _ in 0..nel {
            let (len, value, bounds) = (r.u32()?, r.u32()?, r.u32()?);
            let name = r.name(len)?;
            let (dominates, types) = (r.bitmap()?, r.bitmap()?);
            // The role every object has is the first.
            if name == "object_r" && value != 1 {
                return bad("object_r is not role 1");
            }
            place(&mut table, nprim, value, Role { name, bounds, dominates, types }, "role")?;
        }
        self.roles = filled(table, "role")?;
        Ok(())
    }

    fn read_types(&mut self, r: &mut Reader<'_>) -> Res<()> {
        const PRIMARY: u32 = 1;
        const ATTRIBUTE: u32 = 2;
        let (nprim, nel) = r.table()?;
        let mut table = vec![None; nprim as usize];
        for _ in 0..nel {
            let (len, value, prop, bounds) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
            let ty = Type { name: r.name(len)?, primary: prop & PRIMARY != 0, attribute: prop & ATTRIBUTE != 0, bounds };
            // An alias has its type's number and is not primary: the type
            // keeps the place.
            if !ty.primary {
                if value == 0 || value > nprim {
                    return bad(format!("type alias number {value}"));
                }
                self.type_aliases.insert(ty.name, value);
                continue;
            }
            place(&mut table, nprim, value, ty, "type")?;
        }
        self.types = filled(table, "type")?;
        Ok(())
    }

    fn read_level(r: &mut Reader<'_>) -> Res<Level> {
        Ok(Level { sens: r.u32()?, cats: r.bitmap()? })
    }

    /// `mls_read_range_helper`: one sensitivity or two, then as many
    /// category sets.
    fn read_range(&self, r: &mut Reader<'_>) -> Res<Range> {
        let items = r.u32()?;
        if items == 0 || items > 2 {
            return bad("a range of neither one level nor two");
        }
        let low_sens = r.u32()?;
        let high_sens = if items > 1 { r.u32()? } else { low_sens };
        let low_cats = r.bitmap()?;
        let high_cats = if items > 1 { r.bitmap()? } else { low_cats.clone() };
        Ok(Range { low: Level { sens: low_sens, cats: low_cats }, high: Level { sens: high_sens, cats: high_cats } })
    }

    fn read_users(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let (nprim, nel) = r.table()?;
        let mut table = vec![None; nprim as usize];
        for _ in 0..nel {
            let (len, value, bounds) = (r.u32()?, r.u32()?, r.u32()?);
            let mut user = User { name: r.name(len)?, bounds, roles: r.bitmap()?, ..User::default() };
            if self.mls {
                user.range = self.read_range(r)?;
                user.default_level = Self::read_level(r)?;
            }
            place(&mut table, nprim, value, user, "user")?;
        }
        self.users = filled(table, "user")?;
        Ok(())
    }

    fn read_bools(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let (nprim, nel) = r.table()?;
        let mut table = vec![None; nprim as usize];
        for _ in 0..nel {
            let (value, state, len) = (r.u32()?, r.u32()?, r.u32()?);
            if state > 1 {
                return bad("a boolean that is neither true nor false");
            }
            place(&mut table, nprim, value, Bool { name: r.name(len)?, state: state == 1 }, "boolean")?;
        }
        self.bools = filled(table, "boolean")?;
        Ok(())
    }

    fn read_sensitivities(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let (nprim, nel) = r.table()?;
        self.nsens = nprim;
        for _ in 0..nel {
            let (len, alias) = (r.u32()?, r.u32()?);
            let name = r.name(len)?;
            let level = Self::read_level(r)?;
            self.sensitivities.push(Sensitivity { name, alias: alias != 0, level });
        }
        Ok(())
    }

    fn read_categories(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let (nprim, nel) = r.table()?;
        self.ncats = nprim;
        for _ in 0..nel {
            let (len, value, alias) = (r.u32()?, r.u32()?, r.u32()?);
            self.categories.push((value, Category { name: r.name(len)?, alias: alias != 0 }));
        }
        Ok(())
    }

    /// What `policydb_index` and the datum readers check between them.
    fn check_symbols(&self) -> Res<()> {
        if self.roles.first().is_none_or(|r| r.name != "object_r") {
            return bad("object_r is not role 1");
        }
        for s in &self.sensitivities {
            if s.level.sens == 0 || s.level.sens > self.nsens {
                return bad(format!("sensitivity {} is number {}", s.name, s.level.sens));
            }
        }
        for (value, c) in &self.categories {
            if *value == 0 || *value > self.ncats {
                return bad(format!("category {} is number {value}", c.name));
            }
        }
        for c in &self.classes {
            let own = c.perms.len() as u32 + c.common.map_or(0, |n| self.commons[n as usize - 1].perms.len() as u32);
            if c.nperms > 32 || own > 32 {
                return bad(format!("class {} has more than 32 permissions", c.name));
            }
        }
        Ok(())
    }

    /// `policydb_bounds_sanity_check`: a bound is something that is
    /// there, and no chain of them is a loop.
    fn check_bounds(&self) -> Res<()> {
        let walk = |n: usize, bounds: &dyn Fn(usize) -> u32, what: &str| -> Res<()> {
            for start in 0..n {
                let (mut at, mut depth) = (start, 0);
                while bounds(at) != 0 {
                    let up = bounds(at) as usize;
                    depth += 1;
                    if up > n || depth > 4 {
                        return bad(format!("a {what} bounded by none, or past four deep"));
                    }
                    at = up - 1;
                }
            }
            Ok(())
        };
        walk(self.users.len(), &|i| self.users[i].bounds, "user")?;
        walk(self.roles.len(), &|i| self.roles[i].bounds, "role")?;
        walk(self.types.len(), &|i| self.types[i].bounds, "type")
    }

    // -- what a number or a name stands for -----------------------------------

    pub fn class_ok(&self, class: u32) -> bool {
        class != 0 && class as usize <= self.classes.len()
    }

    pub fn role_ok(&self, role: u32) -> bool {
        role != 0 && role as usize <= self.roles.len()
    }

    pub fn type_ok(&self, ty: u32) -> bool {
        ty != 0 && ty as usize <= self.types.len()
    }

    pub fn class_named(&self, name: &str) -> Option<u32> {
        self.classes.iter().position(|c| c.name == name).map(|i| i as u32 + 1)
    }

    /// The bit of permission `name` in class `class`'s access vectors: its
    /// own, or its common's.
    pub fn perm_named(&self, class: u32, name: &str) -> Option<u32> {
        let c = self.classes.get(class.checked_sub(1)? as usize)?;
        let value = c.perms.get(name).or_else(|| self.commons.get(c.common? as usize - 1)?.perms.get(name))?;
        Some(1 << (value - 1))
    }

    /// A class's permissions with their numbers, its common's first: what
    /// selinuxfs lists under `class/<name>/perms`, each file reading its
    /// number. Permission `n` is bit `n - 1` of an access vector.
    pub fn perms_of(&self, class: u32) -> Vec<(u32, &str)> {
        let Some(c) = class.checked_sub(1).and_then(|i| self.classes.get(i as usize)) else { return Vec::new() };
        let common = c.common.and_then(|n| self.commons.get(n as usize - 1));
        let mut all: Vec<(u32, &str)> = common.into_iter().flat_map(|c| c.perms.iter()).chain(c.perms.iter()).map(|(name, &n)| (n, name.as_str())).collect();
        all.sort();
        all
    }

    /// How a filesystem of type `fstype` labels its files
    /// ([`fs_use`]), and the context the filesystem itself has
    /// (`security_fs_use`): what an `fs_use_*` rule says; or, with none,
    /// by `genfscon`, the filesystem's context being what genfscon gives
    /// its root directory; or, with neither, not at all, when the
    /// filesystem is unlabeled (`None`).
    pub fn fs_use(&self, fstype: &str) -> (u32, Option<&Context>) {
        for c in &self.fs_use {
            if let OContext::FsUse { behavior, fstype: f, context } = c {
                if f == fstype {
                    return (*behavior, Some(context));
                }
            }
        }
        match self.class_named("dir").and_then(|dir| self.genfs_context(fstype, "/", dir)) {
            Some(context) => (fs_use::GENFS, Some(context)),
            None => (fs_use::NONE, None),
        }
    }

    /// The context `genfscon` gives the file at `path` (from its
    /// filesystem's root, with a leading slash) of a filesystem of type
    /// `fstype`, as a `class` (`__security_genfs_sid`): the first rule of
    /// the filesystem's, longest path first, that is for the class or
    /// for any and whose path the file's begins with; with the
    /// `genfs_seclabel_wildcard` capability, whose pattern (`*`, `?`) the
    /// whole path matches. `None` where no rule does: the file is
    /// unlabeled.
    pub fn genfs_context(&self, fstype: &str, path: &str, class: u32) -> Option<&Context> {
        /// `POLICYDB_CAP_GENFS_SECLABEL_WILDCARD`.
        const CAP_GENFS_SECLABEL_WILDCARD: u32 = 11;
        let mut path = path;
        while path.starts_with("//") {
            path = &path[1..];
        }
        let (_, rules) = self.genfs.iter().find(|(f, _)| f == fstype)?;
        let wildcard = self.policycaps.get(CAP_GENFS_SECLABEL_WILDCARD);
        rules
            .iter()
            .find(|r| (r.class == 0 || r.class == class) && if wildcard { wildcard_matches(r.path.as_bytes(), path.as_bytes()) } else { path.starts_with(r.path.as_str()) })
            .map(|r| &r.context)
    }

    fn level_ok(&self, l: &Level) -> bool {
        l.sens != 0 && l.sens <= self.nsens && l.cats.len() <= self.ncats as u64
    }

    /// `mls_range_isvalid`: two levels that are levels, the high one
    /// dominating the low.
    fn range_ok(&self, r: &Range) -> bool {
        self.level_ok(&r.low) && self.level_ok(&r.high) && r.high.sens >= r.low.sens && r.low.cats.within(&r.high.cats)
    }

    /// `policydb_context_isvalid`: a user, role and type that are there
    /// and may go together, and (with MLS) a range the user may have.
    pub fn context_ok(&self, c: &Context) -> bool {
        if !self.role_ok(c.role) || !self.type_ok(c.ty) || c.user == 0 || c.user as usize > self.users.len() {
            return false;
        }
        // object_r goes with any user and type.
        if c.role != 1 {
            let (role, user) = (&self.roles[c.role as usize - 1], &self.users[c.user as usize - 1]);
            if !role.types.get(c.ty - 1) || !user.roles.get(c.role - 1) {
                return false;
            }
        }
        if !self.mls {
            return true;
        }
        if !self.range_ok(&c.range) {
            return false;
        }
        // Within the user's own range (objects of object_r aside).
        if c.role == 1 {
            return true;
        }
        let u = &self.users[c.user as usize - 1].range;
        let within = |l: &Level| l.sens >= u.low.sens && l.sens <= u.high.sens && l.cats.within(&u.high.cats) && u.low.cats.within(&l.cats);
        within(&c.range.low) && within(&c.range.high)
    }

    // -- contexts as text ---------------------------------------------------------

    fn level_string(&self, l: &Level, out: &mut String) {
        let sens = self.sensitivities.iter().find(|s| !s.alias && s.level.sens == l.sens);
        out.push_str(sens.map_or("?", |s| s.name.as_str()));
        let cat = |bit: u32| self.categories.iter().find(|(v, c)| !c.alias && *v == bit + 1).map_or("?", |(_, c)| c.name.as_str());
        // Runs of categories: `c0.c3` for three or more together, a comma
        // between two and between runs (`mls_sid_to_context`).
        let bits: Vec<u32> = l.cats.bits().collect();
        let mut i = 0;
        while i < bits.len() {
            let mut end = i;
            while end + 1 < bits.len() && bits[end + 1] == bits[end] + 1 {
                end += 1;
            }
            out.push(if i == 0 { ':' } else { ',' });
            out.push_str(cat(bits[i]));
            if end > i {
                out.push(if end - i > 1 { '.' } else { ',' });
                out.push_str(cat(bits[end]));
            }
            i = end + 1;
        }
    }

    /// A context as text, `user:role:type` and with MLS its range
    /// (`context_struct_to_string`): the high level only where it is not
    /// the low one.
    pub fn context_string(&self, c: &Context) -> String {
        let at = |n: u32| n.wrapping_sub(1) as usize;
        let mut out = self.users.get(at(c.user)).map_or("?", |u| u.name.as_str()).to_string();
        out.push(':');
        out.push_str(self.roles.get(at(c.role)).map_or("?", |r| r.name.as_str()));
        out.push(':');
        out.push_str(self.types.get(at(c.ty)).map_or("?", |t| t.name.as_str()));
        if self.mls {
            out.push(':');
            self.level_string(&c.range.low, &mut out);
            if c.range.low != c.range.high {
                out.push('-');
                self.level_string(&c.range.high, &mut out);
            }
        }
        out
    }

    fn level_from_str(&self, text: &str) -> Option<Level> {
        let (sens, cats) = match text.split_once(':') {
            Some((s, c)) => (s, Some(c)),
            None => (text, None),
        };
        let mut level = Level { sens: self.sensitivities.iter().find(|s| s.name == sens)?.level.sens, cats: Bitmap::default() };
        let cat = |name: &str| self.categories.iter().find(|(_, c)| c.name == name).map(|(v, _)| *v);
        for part in cats.into_iter().flat_map(|c| c.split(',')) {
            match part.split_once('.') {
                // A range: from the first to the second, which is higher.
                Some((from, to)) => {
                    let (from, to) = (cat(from)?, cat(to)?);
                    if from >= to {
                        return None;
                    }
                    (from..=to).for_each(|v| level.cats.set(v - 1));
                }
                None => level.cats.set(cat(part)? - 1),
            }
        }
        Some(level)
    }

    /// The context `text` names (`string_to_context_struct`, with no
    /// default to take a missing range from): a user, a role and a type
    /// by name, a type by an alias too but not an attribute, and with MLS
    /// a range. `None` for text that is no context of this policy.
    pub fn context_from_str(&self, text: &str) -> Option<Context> {
        let (user, rest) = text.split_once(':')?;
        let (role, rest) = rest.split_once(':')?;
        let (ty, range) = match rest.split_once(':') {
            Some((t, r)) => (t, Some(r)),
            None => (rest, None),
        };
        let mut c = Context {
            user: self.users.iter().position(|u| u.name == user)? as u32 + 1,
            role: self.roles.iter().position(|r| r.name == role)? as u32 + 1,
            ty: match self.types.iter().position(|t| t.name == ty) {
                Some(i) if !self.types[i].attribute => i as u32 + 1,
                Some(_) => return None,
                None => *self.type_aliases.get(ty)?,
            },
            range: Range::default(),
        };
        match (self.mls, range) {
            (true, Some(range)) => {
                let (low, high) = match range.split_once('-') {
                    Some((l, h)) => (l, Some(h)),
                    None => (range, None),
                };
                c.range.low = self.level_from_str(low)?;
                c.range.high = match high {
                    Some(h) => self.level_from_str(h)?,
                    None => c.range.low.clone(),
                };
            }
            (false, None) => {}
            // A range the policy has no use for, or none where it needs one.
            _ => return None,
        }
        self.context_ok(&c).then_some(c)
    }

    // -- decisions ---------------------------------------------------------------

    /// What a conditional's expression comes to with the booleans as
    /// `bools` has them (`cond_evaluate_expr`); `None` for one that comes
    /// to nothing, whose rules are then all off.
    fn cond_holds(expr: &[CondExpr], bools: &[bool]) -> Option<bool> {
        const MAX_DEPTH: usize = 10;
        let mut stack: Vec<bool> = Vec::new();
        for e in expr {
            if e.kind == 1 {
                if stack.len() == MAX_DEPTH {
                    return None;
                }
                stack.push(*bools.get(e.boolean as usize - 1)?);
                continue;
            }
            let b = stack.pop()?;
            if e.kind == 2 {
                stack.push(!b);
                continue;
            }
            let a = stack.pop()?;
            stack.push(match e.kind {
                3 => a | b,
                4 => a & b,
                5 => a ^ b,
                6 => a == b,
                _ => a != b,
            });
        }
        stack.first().copied()
    }

    /// `constraint_expr_eval`: whether a constraint's expression holds of
    /// a source and a target context (and for a validatetrans rule, of
    /// the context something is to become).
    fn constraint_holds(&self, expr: &[ConstraintExpr], s: &Context, t: &Context, x: Option<&Context>) -> bool {
        const USER: u32 = 1;
        const ROLE: u32 = 2;
        const TYPE: u32 = 4;
        const TARGET: u32 = 8;
        const XTARGET: u32 = 16;
        let dom = |a: &Level, b: &Level| a.sens >= b.sens && b.cats.within(&a.cats);
        let mut stack: Vec<bool> = Vec::new();
        for e in expr {
            let v = match e.kind {
                1 => !stack.pop().unwrap_or(false),
                2 | 3 => {
                    let (b, a) = (stack.pop().unwrap_or(false), stack.pop().unwrap_or(false));
                    if e.kind == 2 {
                        a & b
                    } else {
                        a | b
                    }
                }
                // An attribute of the source against the target's.
                4 => {
                    let levels = match e.attr {
                        32 => Some((&s.range.low, &t.range.low)),
                        64 => Some((&s.range.low, &t.range.high)),
                        128 => Some((&s.range.high, &t.range.low)),
                        256 => Some((&s.range.high, &t.range.high)),
                        512 => Some((&s.range.low, &s.range.high)),
                        1024 => Some((&t.range.low, &t.range.high)),
                        _ => None,
                    };
                    match (levels, e.attr) {
                        (Some((l1, l2)), _) => match e.op {
                            1 => l1 == l2,
                            2 => l1 != l2,
                            3 => dom(l1, l2),
                            4 => dom(l2, l1),
                            5 => !dom(l1, l2) && !dom(l2, l1),
                            _ => return false,
                        },
                        (None, ROLE) if e.op >= 3 => {
                            let (r1, r2) = (&self.roles[s.role as usize - 1], &self.roles[t.role as usize - 1]);
                            match e.op {
                                3 => r1.dominates.get(t.role - 1),
                                4 => r2.dominates.get(s.role - 1),
                                5 => !r1.dominates.get(t.role - 1) && !r2.dominates.get(s.role - 1),
                                _ => return false,
                            }
                        }
                        (None, USER | ROLE | TYPE) => {
                            let (v1, v2) = match e.attr {
                                USER => (s.user, t.user),
                                ROLE => (s.role, t.role),
                                _ => (s.ty, t.ty),
                            };
                            match e.op {
                                1 => v1 == v2,
                                2 => v1 != v2,
                                _ => return false,
                            }
                        }
                        _ => return false,
                    }
                }
                // An attribute of one context against a set of names.
                5 => {
                    let c = if e.attr & TARGET != 0 {
                        t
                    } else if e.attr & XTARGET != 0 {
                        match x {
                            Some(x) => x,
                            None => return false,
                        }
                    } else {
                        s
                    };
                    let v = if e.attr & USER != 0 {
                        c.user
                    } else if e.attr & ROLE != 0 {
                        c.role
                    } else if e.attr & TYPE != 0 {
                        c.ty
                    } else {
                        return false;
                    };
                    match e.op {
                        1 => e.names.get(v - 1),
                        2 => !e.names.get(v - 1),
                        _ => return false,
                    }
                }
                _ => return false,
            };
            stack.push(v);
        }
        stack.len() == 1 && stack[0]
    }

    /// `context_struct_compute_av`: the rules about every pairing of the
    /// source's type and attributes with the target's, the conditional
    /// ones whose branch is in force, less what a constraint, a change of
    /// role nobody allowed, or the bounds of a bounded type take away.
    fn context_av(&self, s: &Context, t: &Context, class: u32, bools: &[bool]) -> Decision {
        let mut d = Decision { allowed: 0, auditallow: 0, auditdeny: !0, flags: 0 };
        if !self.class_ok(class) || !self.type_ok(s.ty) || !self.type_ok(t.ty) {
            return d;
        }
        let mut rule = |key: &AvKey, datum: &AvDatum| {
            if let AvDatum::Data(v) = datum {
                match key.specified & av::AV {
                    av::ALLOWED => d.allowed |= v,
                    av::AUDITALLOW => d.auditallow |= v,
                    av::AUDITDENY => d.auditdeny &= v,
                    _ => {}
                }
            }
        };
        let in_force: Vec<&(AvKey, AvDatum)> = self
            .conditionals
            .iter()
            .flat_map(|c| match Self::cond_holds(&c.expr, bools) {
                Some(true) => c.when_true.iter(),
                Some(false) => c.when_false.iter(),
                None => [].iter(),
            })
            .collect();
        for i in self.type_attrs[s.ty as usize - 1].bits() {
            for j in self.type_attrs[t.ty as usize - 1].bits() {
                let (source, target) = (i as u16 + 1, j as u16 + 1);
                for specified in [av::ALLOWED, av::AUDITALLOW, av::AUDITDENY] {
                    let key = AvKey { source, target, class: class as u16, specified };
                    if let Some(datum) = self.avtab.get(&key) {
                        rule(&key, datum);
                    }
                }
                for (key, datum) in in_force.iter().filter(|(k, _)| k.source == source && k.target == target && k.class as u32 == class) {
                    rule(key, datum);
                }
            }
        }
        let c = &self.classes[class as usize - 1];
        for constraint in &c.constraints {
            if constraint.perms & d.allowed != 0 && !self.constraint_holds(&constraint.expr, s, t, None) {
                d.allowed &= !constraint.perms;
            }
        }
        // A process may change role only where a role allow says so.
        if c.name == "process" && s.role != t.role {
            let trans = self.perm_named(class, "transition").unwrap_or(0) | self.perm_named(class, "dyntransition").unwrap_or(0);
            if d.allowed & trans != 0 && !self.role_allow.contains(&(s.role, t.role)) {
                d.allowed &= !trans;
            }
        }
        // A bounded type has no more than what bounds it has
        // (`type_attribute_bounds_av`).
        let bounds = self.types[s.ty as usize - 1].bounds;
        if bounds != 0 {
            let lo_s = Context { ty: bounds, ..s.clone() };
            let t_bounds = self.types[t.ty as usize - 1].bounds;
            let lo_t = Context { ty: if t_bounds != 0 { t_bounds } else { t.ty }, ..t.clone() };
            d.allowed &= self.context_av(&lo_s, &lo_t, class, bools).allowed;
        }
        d
    }

    /// What `source` may do to `target` as a `class`, as a program asks
    /// through selinuxfs's `access` (`security_compute_av_user`). `bools`
    /// are the booleans as they now stand.
    pub fn compute_av(&self, source: &Context, target: &Context, class: u32, bools: &[bool]) -> Decision {
        const PERMISSIVE: u32 = 1;
        const NEVERAUDIT: u32 = 2;
        let mut flags = 0;
        if self.permissive.get(source.ty) {
            flags |= PERMISSIVE;
        }
        if self.neveraudit.get(source.ty) {
            flags |= NEVERAUDIT;
        }
        let mut d = if flags == PERMISSIVE | NEVERAUDIT || (class == 0 && self.allow_unknown) {
            Decision { allowed: !0, auditallow: 0, auditdeny: !0, flags: 0 }
        } else {
            self.context_av(source, target, class, bools)
        };
        d.flags = flags;
        if flags & NEVERAUDIT != 0 {
            (d.auditallow, d.auditdeny) = (0, 0);
        }
        d
    }

    /// The context of something new: an object a process of `source`
    /// makes in or on something of `target` (`specified` is
    /// [`av::TRANSITION`]; `name` is the name it is made under, for a
    /// file), a process after it runs a file of `target`, a member of a
    /// polyinstantiated `target` ([`av::MEMBER`]), or what `target` is
    /// relabelled to ([`av::CHANGE`]). `security_compute_sid`.
    ///
    /// The context may be one the policy does not allow
    /// ([`Policy::context_ok`]): a kernel that enforces refuses it
    /// (`EACCES`), and one that does not lets it stand. `None` where there
    /// is no context to give (`EINVAL`).
    pub fn compute_context(&self, source: &Context, target: &Context, class: u32, specified: u16, name: Option<&str>, bools: &[bool]) -> Option<Context> {
        const SOURCE: u32 = 1;
        const TARGET: u32 = 2;
        let c = self.classes.get(class.wrapping_sub(1) as usize);
        let process = c.is_some_and(|c| c.name == "process");
        // A socket takes after the process that makes it; so the kernel
        // treats the classes it knows as sockets, all named so.
        let own = process || c.is_some_and(|c| is_socket_class(&c.name));
        let default = |of: &dyn Fn(&Class) -> u32| c.map_or(0, of);
        let mut new = Context::default();
        new.user = match specified {
            av::MEMBER => target.user,
            _ if default(&|c| c.default_user) == TARGET => target.user,
            _ => source.user,
        };
        new.role = match default(&|c| c.default_role) {
            SOURCE => source.role,
            TARGET => target.role,
            _ if own => source.role,
            _ => 1,
        };
        // A rule for the pair, a conditional one in force if no other,
        // else the class's default, else the process's or the object's.
        let key = AvKey { source: source.ty as u16, target: target.ty as u16, class: class as u16, specified };
        let rule = self.avtab.get(&key).or_else(|| {
            self.conditionals.iter().find_map(|cond| {
                let list = match Self::cond_holds(&cond.expr, bools)? {
                    true => &cond.when_true,
                    false => &cond.when_false,
                };
                list.iter().find(|(k, _)| AvKey { specified: k.specified & !av::ENABLED, ..*k } == key).map(|(_, d)| d)
            })
        });
        new.ty = match (rule, default(&|c| c.default_type)) {
            (Some(AvDatum::Data(ty)), _) => *ty,
            (_, SOURCE) => source.ty,
            (_, TARGET) => target.ty,
            _ if own => source.ty,
            _ => target.ty,
        };
        if let Some(name) = name {
            if let Some(rules) = self.filename_trans.get(&(target.ty, class, name.to_string())) {
                if let Some(t) = rules.iter().find(|t| t.stypes.get(source.ty.wrapping_sub(1))) {
                    new.ty = t.otype;
                }
            }
        }
        if specified & av::TRANSITION != 0 {
            if let Some(&role) = self.role_trans.get(&(source.role, target.ty, class)) {
                new.role = role;
            }
        }
        if !self.mls {
            return Some(new);
        }
        // `mls_compute_sid`.
        let low = |c: &Context| Range { low: c.range.low.clone(), high: c.range.low.clone() };
        let high = |c: &Context| Range { low: c.range.high.clone(), high: c.range.high.clone() };
        new.range = match specified {
            av::TRANSITION => match (self.range_trans.get(&(source.ty, target.ty, class)), default(&|c| c.default_range)) {
                (Some(range), _) => range.clone(),
                (_, 1) => low(source),
                (_, 2) => high(source),
                (_, 3) => source.range.clone(),
                (_, 4) => low(target),
                (_, 5) => high(target),
                (_, 6) => target.range.clone(),
                // The greatest of the low levels and the least of the high.
                (_, 7) => {
                    let (a, b) = (&source.range, &target.range);
                    if a.high.sens < b.low.sens || b.high.sens < a.low.sens {
                        return None;
                    }
                    Range {
                        low: Level { sens: a.low.sens.max(b.low.sens), cats: a.low.cats.and(&b.low.cats) },
                        high: Level { sens: a.high.sens.min(b.high.sens), cats: a.high.cats.and(&b.high.cats) },
                    }
                }
                _ if own => source.range.clone(),
                _ => low(source),
            },
            av::CHANGE if own => source.range.clone(),
            av::CHANGE | av::MEMBER => low(source),
            _ => return None,
        };
        Some(new)
    }

    /// Whether something of `class` may be relabelled from `old` to `new`
    /// by a process of `task`: every validatetrans rule of the class
    /// holds of the three (`security_validate_transition`, which a program
    /// asks through selinuxfs's `validatetrans`). `None` for a class the
    /// policy has not.
    pub fn validate_transition(&self, old: &Context, new: &Context, task: &Context, class: u32) -> Option<bool> {
        let c = self.classes.get(class.checked_sub(1)? as usize)?;
        Some(c.validatetrans.iter().all(|rule| self.constraint_holds(&rule.expr, old, new, Some(task))))
    }

    /// A context of policy `old` in this policy's terms, name by name
    /// (`convert_context`, when one policy takes another's place): its
    /// user, role and type, and with MLS its sensitivities and categories.
    /// `None` where this policy lacks one of the names. The result may be
    /// a context this policy does not allow ([`Policy::context_ok`]).
    pub fn convert_context(&self, old: &Policy, c: &Context) -> Option<Context> {
        let at = |n: u32| n.checked_sub(1).map(|i| i as usize);
        let user = &old.users.get(at(c.user)?)?.name;
        let role = &old.roles.get(at(c.role)?)?.name;
        let ty = &old.types.get(at(c.ty)?)?.name;
        let mut new = Context {
            user: self.users.iter().position(|u| u.name == *user)? as u32 + 1,
            role: self.roles.iter().position(|r| r.name == *role)? as u32 + 1,
            // A type's name may now be an alias, or an attribute's.
            ty: match self.types.iter().position(|t| t.name == *ty) {
                Some(i) => i as u32 + 1,
                None => *self.type_aliases.get(ty)?,
            },
            range: Range::default(),
        };
        if !self.mls {
            return Some(new);
        }
        if !old.mls {
            // From a policy with no levels: the unlabeled SID's range.
            new.range = self.initial_sids.iter().find_map(|o| match o {
                OContext::InitialSid { sid: 3, context } => Some(context.range.clone()),
                _ => None,
            })?;
            return Some(new);
        }
        let level = |l: &Level| -> Option<Level> {
            let sens = &old.sensitivities.iter().find(|s| !s.alias && s.level.sens == l.sens)?.name;
            let mut out = Level { sens: self.sensitivities.iter().find(|s| s.name == *sens)?.level.sens, cats: Bitmap::default() };
            for bit in l.cats.bits() {
                let name = &old.categories.iter().find(|(v, c)| !c.alias && *v == bit + 1)?.1.name;
                out.cats.set(self.categories.iter().find(|(_, c)| c.name == *name)?.0 - 1);
            }
            Some(out)
        };
        new.range = Range { low: level(&c.range.low)?, high: level(&c.range.high)? };
        Some(new)
    }

    /// The booleans as the policy starts them.
    pub fn bool_defaults(&self) -> Vec<bool> {
        self.bools.iter().map(|b| b.state).collect()
    }

    // -- rules -------------------------------------------------------------------

    /// `avtab_read_item`, the form since version 20.
    fn read_av(&self, r: &mut Reader<'_>, conditional: bool) -> Res<(AvKey, AvDatum)> {
        let key = AvKey { source: r.u16()?, target: r.u16()?, class: r.u16()?, specified: r.u16()? };
        if !self.type_ok(key.source as u32) || !self.type_ok(key.target as u32) || !self.class_ok(key.class as u32) {
            return bad("a rule about a type or class that is not there");
        }
        let kinds = (key.specified & (av::XPERMS | av::TYPE | av::AV)).count_ones();
        if kinds != 1 {
            return bad("a rule of no kind, or of two");
        }
        if key.specified & av::XPERMS != 0 {
            if self.version < VERSION_XPERMS_IOCTL || (conditional && self.version < VERSION_COND_XPERMS) {
                return bad("an extended permission rule where the version has none");
            }
            let (specified, driver) = (r.u8()?, r.u8()?);
            let mut perms = [0u32; 8];
            for p in &mut perms {
                *p = r.u32()?;
            }
            return Ok((key, AvDatum::Xperms(Xperms { specified, driver, perms })));
        }
        let data = r.u32()?;
        if key.specified & av::TYPE != 0 && !self.type_ok(data) {
            return bad("a transition to a type that is not there");
        }
        Ok((key, AvDatum::Data(data)))
    }

    fn read_conditionals(&mut self, r: &mut Reader<'_>) -> Res<()> {
        for _ in 0..r.u32()? {
            let (_state, len) = (r.u32()?, r.u32()?);
            let mut cond = Conditional::default();
            for _ in 0..len {
                let e = CondExpr { kind: r.u32()?, boolean: r.u32()? };
                if e.kind == 0 || e.kind > 7 || e.boolean as usize > self.bools.len() || (e.kind == 1 && e.boolean == 0) {
                    return bad("a conditional expression that is not one");
                }
                cond.expr.push(e);
            }
            for _ in 0..r.u32()? {
                cond.when_true.push(self.read_av(r, true)?);
            }
            for _ in 0..r.u32()? {
                cond.when_false.push(self.read_av(r, true)?);
            }
            self.conditionals.push(cond);
        }
        Ok(())
    }

    fn read_filename_trans(&mut self, r: &mut Reader<'_>) -> Res<()> {
        if self.version < VERSION_FILENAME_TRANS {
            return Ok(());
        }
        let n = r.u32()?;
        for _ in 0..n {
            let len = r.u32()?;
            let name = r.name(len)?;
            if self.version < VERSION_COMP_FTRANS {
                // One source type a rule.
                let (stype, ttype, class, otype) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                if !self.type_ok(stype) || !self.type_ok(ttype) || !self.class_ok(class) || !self.type_ok(otype) {
                    return bad("a file-name transition of something that is not there");
                }
                let rules = self.filename_trans.entry((ttype, class, name)).or_default();
                // A source type keeps the first rule it had.
                if rules.iter().any(|t| t.stypes.get(stype - 1)) {
                    continue;
                }
                match rules.iter_mut().find(|t| t.otype == otype) {
                    Some(t) => t.stypes.set(stype - 1),
                    None => {
                        let mut stypes = Bitmap::default();
                        stypes.set(stype - 1);
                        rules.push(FilenameTrans { stypes, otype });
                    }
                }
                continue;
            }
            let (ttype, class, ndatum) = (r.u32()?, r.u32()?, r.u32()?);
            if ndatum == 0 || !self.type_ok(ttype) || !self.class_ok(class) {
                return bad("a file-name transition of something that is not there");
            }
            let mut rules = Vec::new();
            for _ in 0..ndatum {
                let stypes = r.bitmap()?;
                let otype = r.u32()?;
                if !self.type_ok(otype) || stypes.len() > self.types.len() as u64 {
                    return bad("a file-name transition of a type that is not there");
                }
                rules.push(FilenameTrans { stypes, otype });
            }
            if self.filename_trans.insert((ttype, class, name), rules).is_some() {
                return bad("a file-name transition twice");
            }
        }
        Ok(())
    }

    fn read_context(&self, r: &mut Reader<'_>) -> Res<Context> {
        let mut c = Context { user: r.u32()?, role: r.u32()?, ty: r.u32()?, range: Range::default() };
        // The range is there whether or not the policy uses it.
        c.range = self.read_range(r)?;
        if !self.context_ok(&c) {
            return bad(format!("a context that is not one: user {} role {} type {}", c.user, c.role, c.ty));
        }
        Ok(c)
    }

    fn read_ocontexts(&mut self, r: &mut Reader<'_>, tables: u32) -> Res<()> {
        for table in 0..tables {
            for _ in 0..r.u32()? {
                match table {
                    0 => {
                        let sid = r.u32()?;
                        let context = self.read_context(r)?;
                        self.initial_sids.push(OContext::InitialSid { sid, context });
                    }
                    1 | 3 => {
                        let len = r.u32()?;
                        let name = r.name(len)?;
                        let context = [self.read_context(r)?, self.read_context(r)?];
                        if table == 1 {
                            self.fs.push(OContext::Fs { name, context });
                        } else {
                            self.netifs.push(OContext::Netif { name, context });
                        }
                    }
                    2 => {
                        let (protocol, low, high) = (r.u32()?, r.u32()?, r.u32()?);
                        let context = self.read_context(r)?;
                        self.ports.push(OContext::Port { protocol, low, high, context });
                    }
                    4 => {
                        let (addr, mask) = (r.u32()?, r.u32()?);
                        let context = self.read_context(r)?;
                        self.nodes.push(OContext::Node { addr, mask, context });
                    }
                    5 => {
                        let (behavior, len) = (r.u32()?, r.u32()?);
                        // Up to SECURITY_FS_USE_NATIVE; a mount point's is
                        // found when it is mounted, never written here.
                        if behavior == 6 || behavior > 7 {
                            return bad(format!("fs_use behaviour {behavior}"));
                        }
                        let fstype = r.name(len)?;
                        let context = self.read_context(r)?;
                        self.fs_use.push(OContext::FsUse { behavior, fstype, context });
                    }
                    6 => {
                        let mut words = [0u32; 8];
                        for w in &mut words {
                            *w = r.u32()?;
                        }
                        let context = self.read_context(r)?;
                        self.nodes6.push(OContext::Node6 { addr: words[..4].try_into().unwrap(), mask: words[4..].try_into().unwrap(), context });
                    }
                    7 => {
                        let subnet_prefix = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
                        let (low, high) = (r.u32()?, r.u32()?);
                        if low > 0xffff || high > 0xffff {
                            return bad("an InfiniBand partition key past 16 bits");
                        }
                        let context = self.read_context(r)?;
                        self.ib_pkeys.push(OContext::IbPkey { subnet_prefix, low, high, context });
                    }
                    _ => {
                        let (len, port) = (r.u32()?, r.u32()?);
                        let name = r.name(len)?;
                        if port == 0 || port > 0xff {
                            return bad("an InfiniBand port that is not one");
                        }
                        let context = self.read_context(r)?;
                        self.ib_end_ports.push(OContext::IbEndPort { name, port, context });
                    }
                }
            }
        }
        Ok(())
    }

    fn read_genfs(&mut self, r: &mut Reader<'_>) -> Res<()> {
        for _ in 0..r.u32()? {
            let len = r.u32()?;
            let fstype = r.name(len)?;
            if self.genfs.iter().any(|(f, _)| *f == fstype) {
                return bad(format!("genfs contexts for {fstype} twice"));
            }
            let mut paths: Vec<GenfsPath> = Vec::new();
            for _ in 0..r.u32()? {
                let len = r.u32()?;
                let path = r.name(len)?;
                let class = r.u32()?;
                let context = self.read_context(r)?;
                if paths.iter().any(|p| p.path == path && (p.class == 0 || class == 0 || p.class == class)) {
                    return bad(format!("genfs context for {fstype} {path} twice"));
                }
                // Longest first, and after the others of its length.
                let at = paths.iter().position(|p| path.len() > p.path.len()).unwrap_or(paths.len());
                paths.insert(at, GenfsPath { path, class, context });
            }
            self.genfs.push((fstype, paths));
        }
        self.genfs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // testdata/test.conf compiled by checkpolicy 3.5 (`checkpolicy -M -c
    // 30` and `-c 33`): one of everything a policy can hold. The two
    // versions differ in how file-name transitions are written.

    fn ty(p: &Policy, name: &str) -> u32 {
        p.types.iter().position(|t| t.name == name).unwrap_or_else(|| panic!("no type {name}")) as u32 + 1
    }

    fn av(p: &Policy, source: &str, target: &str, class: &str, specified: u16) -> Option<u32> {
        let key = AvKey { source: ty(p, source) as u16, target: ty(p, target) as u16, class: p.class_named(class).unwrap() as u16, specified };
        match p.avtab.get(&key) {
            Some(AvDatum::Data(d)) => Some(*d),
            _ => None,
        }
    }

    /// Everything in the source is read, as the source says it and as
    /// setools counts it in the same file (the numbers in the comments).
    #[test]
    fn a_compiled_policy_is_read_as_its_source_says() {
        let v30: &[u8] = fixture!("test.30");
        let v33: &[u8] = fixture!("test.33");
        for (bytes, version) in [(v30, 30), (v33, 33)] {
            let p = Policy::read(bytes).unwrap();
            assert_eq!((p.version, p.mls, p.allow_unknown, p.reject_unknown, p.trailing), (version, true, false, false, 0));
            // Classes 4, Permissions 15, Types 7, Attributes 2, Users 2,
            // Roles 3, Booleans 2.
            assert_eq!(p.classes.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["process", "file", "dir", "binder"]);
            let perms: usize = p.commons.iter().map(|c| c.perms.len()).sum::<usize>() + p.classes.iter().map(|c| c.perms.len()).sum::<usize>();
            assert_eq!((perms, p.types.len(), p.types.iter().filter(|t| t.attribute).count(), p.users.len(), p.roles.len(), p.bools.len()), (15, 9, 2, 2, 3, 2));
            assert_eq!(p.roles[0].name, "object_r");
            assert_eq!(p.policycaps.bits().collect::<Vec<_>>(), [0, 1]);
            assert_eq!(p.permissive.bits().collect::<Vec<_>>(), [ty(&p, "app_t")], "a permissive type, by its number");

            // A class's permissions come after its common's.
            let file = p.class_named("file").unwrap();
            assert_eq!((p.perm_named(file, "read"), p.perm_named(file, "ioctl"), p.perm_named(file, "execute"), p.perm_named(file, "open"), p.perm_named(file, "search")), (Some(1), Some(8), Some(16), Some(64), None));
            let c = &p.classes[file as usize - 1];
            assert_eq!((c.default_user, c.default_role, c.default_type, c.default_range), (1, 0, 2, 4), "source user, target type, the target's low level");
            assert_eq!((c.constraints.len(), c.validatetrans.len()), (1, 2), "mlsconstrain; mlsvalidatetrans and validatetrans");
            assert_eq!(p.classes[0].constraints.len(), 1);

            // Sensitivities and categories, with their aliases.
            let sens: Vec<_> = p.sensitivities.iter().map(|s| (s.name.as_str(), s.alias, s.level.sens)).collect();
            assert!(sens.contains(&("s0", false, 1)) && sens.contains(&("s1", false, 2)) && sens.contains(&("secret", true, 2)) && sens.len() == 3);
            assert!(p.categories.iter().any(|(v, c)| (*v, c.name.as_str(), c.alias) == (2, "first", true)));
            let system = p.users.iter().find(|u| u.name == "system_u").unwrap();
            assert_eq!((system.range.low.sens, system.range.high.sens, system.range.high.cats.bits().collect::<Vec<_>>(), system.range.low.cats.is_empty()), (1, 2, vec![0, 1, 2], true));

            // Types: an alias is its type, a bound is kept, and each has
            // itself and its attributes.
            assert!(p.types.iter().all(|t| t.name != "old_file_t"));
            assert_eq!(p.types[ty(&p, "child_t") as usize - 1].bounds, ty(&p, "init_t"));
            let attrs: Vec<u32> = p.type_attrs[ty(&p, "init_t") as usize - 1].bits().map(|b| b + 1).collect();
            let mut want = vec![ty(&p, "init_t"), ty(&p, "domain")];
            want.sort();
            assert_eq!(attrs, want);

            // Allow 7 (two of them conditional), Auditallow 1, Dontaudit 1,
            // Type_trans 4 (three by file name), Type_change 1, Type_member 1.
            assert_eq!(av(&p, "init_t", "exec_t", "file", av::ALLOWED), Some(1 | 16 | 64), "read, execute, open");
            assert_eq!(av(&p, "domain", "file_type", "file", av::ALLOWED), Some(1 | 4), "a rule on attributes stays on them");
            assert_eq!(av(&p, "app_t", "file_t", "file", av::AUDITALLOW), Some(2));
            assert_eq!(av(&p, "app_t", "tmp_t", "dir", av::AUDITDENY), Some(!16), "dontaudit: everything but search is audited");
            assert_eq!(av(&p, "init_t", "exec_t", "process", av::TRANSITION), Some(ty(&p, "app_t")));
            assert_eq!(av(&p, "app_t", "file_t", "file", av::CHANGE), Some(ty(&p, "tmp_t")));
            assert_eq!(av(&p, "app_t", "tmp_t", "dir", av::MEMBER), Some(ty(&p, "tmp_t")));
            assert_eq!(p.avtab.len(), 10);
            // Allowxperm 2: one for each ioctl driver byte.
            let mut x: Vec<_> = p.xperms.iter().map(|(k, x)| (k.specified, x.specified, x.driver, x.perms[0])).collect();
            x.sort();
            assert_eq!(x, [(av::XPERMS_ALLOWED, 1, 0x54, 0x1fffe), (av::XPERMS_ALLOWED, 1, 0x89, 2)]);

            // if (allow_stuff && !other_thing): the two booleans, NOT, AND.
            let cond = &p.conditionals[0];
            assert_eq!(cond.expr.iter().map(|e| e.kind).collect::<Vec<_>>(), [1, 1, 2, 4]);
            let named = |i: usize| p.bools[cond.expr[i].boolean as usize - 1].name.as_str();
            assert_eq!((named(0), named(1)), ("allow_stuff", "other_thing"));
            let tmp_file = |specified| AvKey { source: ty(&p, "app_t") as u16, target: ty(&p, "tmp_t") as u16, class: file as u16, specified };
            assert_eq!(cond.when_true, [(tmp_file(av::ALLOWED | av::ENABLED), AvDatum::Data(2))], "write, in force: allow_stuff is true");
            assert_eq!(cond.when_false, [(tmp_file(av::ALLOWED), AvDatum::Data(64))], "open, not in force");

            // File-name transitions, the same from either form.
            let special = &p.filename_trans[&(ty(&p, "tmp_t"), file, "special".to_string())];
            assert_eq!(special.len(), 1);
            let mut from: Vec<u32> = special[0].stypes.bits().map(|b| b + 1).collect();
            from.sort();
            let mut both = vec![ty(&p, "app_t"), ty(&p, "init_t")];
            both.sort();
            assert_eq!((from, special[0].otype), (both, ty(&p, "file_t")));
            assert_eq!(p.filename_trans.len(), 2);

            // Role_trans 1, Role allow 1, Range_trans 1.
            let role = |name: &str| p.roles.iter().position(|r| r.name == name).unwrap() as u32 + 1;
            assert_eq!(p.role_trans[&(role("system_r"), ty(&p, "exec_t"), 1)], role("app_r"));
            assert_eq!(p.role_allow, [(role("system_r"), role("app_r"))]);
            let range = &p.range_trans[&(ty(&p, "init_t"), ty(&p, "exec_t"), 1)];
            assert_eq!((range.low.sens, range.high.sens, range.high.cats.bits().collect::<Vec<_>>()), (2, 2, vec![0, 1]));

            // Initial SIDs 27, Fs_use 3, Genfscon 5, Portcon 2, Netifcon 1,
            // Nodecon 2.
            assert_eq!((p.initial_sids.len(), p.fs_use.len(), p.ports.len(), p.netifs.len(), p.nodes.len(), p.nodes6.len()), (27, 3, 2, 1, 1, 1));
            // The fifth, `file`, has a range of its own.
            assert!(p.initial_sids.iter().any(|c| matches!(c, OContext::InitialSid { sid: 5, context } if context.range.high.sens == 2 && context.range.high.cats.count() == 3)));
            assert!(p.fs_use.iter().any(|f| matches!(f, OContext::FsUse { behavior: 1, fstype, .. } if fstype == "ext4")));
            // A filesystem's paths, longest first; one for files alone.
            let (fstype, paths) = &p.genfs[0];
            assert_eq!(fstype, "proc");
            assert_eq!(paths.iter().map(|g| (g.path.as_str(), g.class)).collect::<Vec<_>>(), [("/sys/kernel", file), ("/sys", 0), ("/", 0)]);
            assert_eq!(paths[0].context.ty, ty(&p, "exec_t"));
        }
    }

    /// A policy cut short anywhere, or with a number changed, is refused
    /// or read; it is never a panic, and never memory for what is not
    /// there.
    #[test]
    fn a_damaged_policy_is_refused() {
        let v33: &[u8] = fixture!("test.33");
        assert_eq!(Policy::read(b"").err(), Some(Bad("truncated at byte 0".into())));
        assert!(Policy::read(&v33[..v33.len() - 1]).is_err());
        for cut in (0..v33.len()).step_by(7) {
            assert!(Policy::read(&v33[..cut]).is_err(), "cut at {cut}");
        }
        // Each word in turn made enormous.
        for at in (0..v33.len() - 4).step_by(4) {
            let mut bytes = v33.to_vec();
            bytes[at..at + 4].copy_from_slice(&0x7fff_fff0u32.to_le_bytes());
            let _ = Policy::read(&bytes);
        }
        let mut old = v33.to_vec();
        old[16..20].copy_from_slice(&23u32.to_le_bytes());
        assert!(Policy::read(&old).err().is_some_and(|e| e.0.contains("version 23")));
    }

    /// A context is read from text and written back as the kernel writes
    /// it; text that names what the policy has not, or puts together what
    /// it does not allow together, is no context.
    #[test]
    fn a_context_is_read_from_text_and_written_back() {
        let v33: &[u8] = fixture!("test.33");
        let p = Policy::read(v33).unwrap();
        for text in [
            "system_u:system_r:kernel_t:s0",
            "system_u:object_r:file_t:s0-s1:c0.c2",
            "system_u:system_r:init_t:s0:c0,c2",
            "system_u:system_r:init_t:s0:c0,c1",
            "system_u:system_r:init_t:s0-s1",
            "system_u:system_r:init_t:s1:c1-s1:c0.c2",
            "app_u:app_r:app_t:s0-s0:c0",
            "app_u:object_r:tmp_t:s1:c0.c2",
        ] {
            let c = p.context_from_str(text).unwrap_or_else(|| panic!("{text} is a context"));
            assert_eq!(p.context_string(&c), text);
        }
        // Other spellings of the same: aliases, a range of two written
        // with a dot, a high level that is the low one.
        for (text, written) in [
            ("system_u:object_r:old_file_t:s0", "system_u:object_r:file_t:s0"),
            ("system_u:system_r:init_t:secret", "system_u:system_r:init_t:s1"),
            ("system_u:system_r:init_t:s0:c0.c1", "system_u:system_r:init_t:s0:c0,c1"),
            ("system_u:system_r:init_t:s0:first", "system_u:system_r:init_t:s0:c1"),
            ("system_u:system_r:init_t:s0-s0", "system_u:system_r:init_t:s0"),
        ] {
            let c = p.context_from_str(text).unwrap_or_else(|| panic!("{text} is a context"));
            assert_eq!(p.context_string(&c), written);
        }
        for text in [
            "",
            "system_u:system_r",
            "system_u:system_r:init_t",
            "nobody:system_r:init_t:s0",
            "system_u:nothing_r:init_t:s0",
            "system_u:system_r:nothing_t:s0",
            // An attribute is not a type a context can have.
            "system_u:system_r:domain:s0",
            // A role the user has not, and a type the role has not.
            "app_u:system_r:init_t:s0",
            "app_u:app_r:init_t:s0",
            // Past the user's range, in sensitivity and in categories.
            "app_u:app_r:app_t:s1",
            "app_u:app_r:app_t:s0:c1",
            // A range that goes down, categories out of order, no such.
            "system_u:system_r:init_t:s1-s0",
            "system_u:system_r:init_t:s0:c2.c0",
            "system_u:system_r:init_t:s0:c9",
            "system_u:system_r:init_t:s0:c0-s0",
            "system_u:system_r:init_t:s0:",
        ] {
            assert_eq!(p.context_from_str(text), None, "{text}");
        }
    }

    /// Ask `p` each question of `answers` (lines of
    /// tests/android/oracle/selinux-ask.py's: a question, an arrow, what a
    /// kernel answered) and hold it to the kernel's answer. How many were
    /// asked.
    fn replay(p: &Policy, answers: &str) -> usize {
        let mut bools = p.bool_defaults();
        let mut asked = 0;
        for line in answers.lines() {
            if line.starts_with('#') {
                continue;
            }
            let Some((question, want)) = line.split_once(" => ") else { continue };
            let words: Vec<&str> = question.split_whitespace().collect();
            let context = |text: &str| p.context_from_str(text).unwrap_or_else(|| panic!("{question}: {text} is a context"));
            let got = match words.as_slice() {
                ["bool", name, value] => {
                    let at = p.bools.iter().position(|b| b.name == *name).unwrap();
                    bools[at] = *value == "1";
                    continue;
                }
                ["context", text] => p.context_from_str(text).map_or("errno EINVAL".to_string(), |c| p.context_string(&c)),
                ["access", s, t, class] => {
                    let d = p.compute_av(&context(s), &context(t), p.class_named(class).unwrap(), &bools);
                    format!("{:x} ffffffff {:x} {:x} {:x}", d.allowed, d.auditallow, d.auditdeny, d.flags)
                }
                [kind @ ("create" | "member" | "relabel"), s, t, class, name @ ..] => {
                    let specified = match *kind {
                        "create" => av::TRANSITION,
                        "member" => av::MEMBER,
                        _ => av::CHANGE,
                    };
                    let new = p.compute_context(&context(s), &context(t), p.class_named(class).unwrap(), specified, name.first().copied(), &bools);
                    new.map_or("errno EINVAL".to_string(), |c| p.context_string(&c))
                }
                ["validatetrans", old, new, class, task] => match p.validate_transition(&context(old), &context(new), &context(task), p.class_named(class).unwrap()) {
                    Some(true) => "ok".to_string(),
                    Some(false) => "errno EPERM".to_string(),
                    None => "errno EINVAL".to_string(),
                },
                // What selinuxfs's files read, of those the policy alone
                // decides; the rest are the kernel's own or the SID
                // table's (`server`).
                ["read", file] => match file.split('/').collect::<Vec<_>>().as_slice() {
                    ["mls"] => (p.mls as u8).to_string(),
                    ["deny_unknown"] => (!p.allow_unknown as u8).to_string(),
                    ["reject_unknown"] => (p.reject_unknown as u8).to_string(),
                    ["class", class, "index"] => p.class_named(class).unwrap().to_string(),
                    ["class", class, "perms", perm] => {
                        let perms = p.perms_of(p.class_named(class).unwrap());
                        let (number, _) = perms.iter().find(|(_, name)| name == perm).unwrap();
                        // Its number is its bit's place.
                        assert_eq!(p.perm_named(p.class_named(class).unwrap(), perm), Some(1 << (number - 1)));
                        number.to_string()
                    }
                    // Its value, and the one waiting to be committed.
                    ["booleans", name] => {
                        let state = bools[p.bools.iter().position(|b| b.name == *name).unwrap()] as u8;
                        format!("{state} {state}")
                    }
                    ["policy_capabilities", name] => {
                        let bit = POLICY_CAPABILITIES.iter().position(|c| c == name).unwrap();
                        (p.policycaps.get(bit as u32) as u8).to_string()
                    }
                    _ => continue,
                },
                _ => panic!("{question}"),
            };
            assert_eq!(got, want, "{question}");
            asked += 1;
        }
        asked
    }

    /// What a Linux kernel answered through selinuxfs with test.33 loaded
    /// (testdata/answers.txt; how they were asked is at its head), and the
    /// same asked of this.
    #[test]
    fn its_answers_are_a_kernels() {
        let v33: &[u8] = fixture!("test.33");
        let asked = replay(&Policy::read(v33).unwrap(), include_str!("testdata/answers.txt"));
        assert!(asked > 400, "{asked} questions");
    }

    /// The same for any policy there is a kernel's answers about:
    /// `GEX_SELINUX_POLICY` names the policy, `GEX_SELINUX_ANSWERS` what
    /// a kernel that had loaded it answered. A system image's policy is
    /// not kept here. The Android 17 image's
    /// (vendor/etc/selinux/precompiled_sepolicy) has been through this
    /// against Linux 7.0, which loads it where 6.8's tools cannot read
    /// it: 6,643 questions of fifteen domains, twenty-three types and the
    /// classes between them, and nine of its selinuxfs files, and no
    /// answer different.
    #[test]
    #[ignore = "needs GEX_SELINUX_POLICY and GEX_SELINUX_ANSWERS"]
    fn its_answers_about_a_policy_given_are_a_kernels() {
        let policy = std::fs::read(std::env::var("GEX_SELINUX_POLICY").expect("GEX_SELINUX_POLICY")).unwrap();
        let answers = std::fs::read_to_string(std::env::var("GEX_SELINUX_ANSWERS").expect("GEX_SELINUX_ANSWERS")).unwrap();
        let asked = replay(&Policy::read(&policy).unwrap(), &answers);
        assert!(asked > 0);
        println!("{asked} questions, each answered as the kernel answered it");
    }

    /// The labelling rules of test.conf, by the reference's lookups:
    /// `fs_use_*` by type, `genfscon` by the longest path a file's begins
    /// with, for its class. (The same lookups over the Android policy
    /// give the labels Linux 7.0 gave: `server`'s
    /// `its_labels_for_a_policy_given_are_a_kernels`.)
    #[test]
    fn a_filesystem_is_labelled_as_the_policy_says() {
        let v33: &[u8] = fixture!("test.33");
        let p = Policy::read(v33).unwrap();
        let text = |c: Option<&Context>| c.map(|c| p.context_string(c));
        let (file, dir) = (p.class_named("file").unwrap(), p.class_named("dir").unwrap());
        assert_eq!((p.fs_use("ext4").0, text(p.fs_use("ext4").1).as_deref()), (fs_use::XATTR, Some("system_u:object_r:file_t:s0")));
        assert_eq!((p.fs_use("pipefs").0, text(p.fs_use("pipefs").1).as_deref()), (fs_use::TASK, Some("system_u:object_r:tmp_t:s0")));
        assert_eq!((p.fs_use("devpts").0, text(p.fs_use("devpts").1).as_deref()), (fs_use::TRANS, Some("system_u:object_r:tmp_t:s0")));
        // No fs_use rule: by genfscon, the filesystem being its root.
        assert_eq!((p.fs_use("proc").0, text(p.fs_use("proc").1).as_deref()), (fs_use::GENFS, Some("system_u:object_r:file_t:s0")));
        assert_eq!((p.fs_use("selinuxfs").0, text(p.fs_use("selinuxfs").1).as_deref()), (fs_use::GENFS, Some("system_u:object_r:tmp_t:s0")));
        // Neither: not labelled.
        assert_eq!(p.fs_use("vfat"), (fs_use::NONE, None));
        let genfs = |path: &str, class: u32| text(p.genfs_context("proc", path, class));
        assert_eq!(genfs("/cpuinfo", file).as_deref(), Some("system_u:object_r:file_t:s0"));
        assert_eq!(genfs("/sys/vm/overcommit_memory", file).as_deref(), Some("system_u:object_r:tmp_t:s0"));
        // The rule for /sys/kernel is for files alone.
        assert_eq!(genfs("/sys/kernel/hostname", file).as_deref(), Some("system_u:object_r:exec_t:s0"));
        assert_eq!(genfs("/sys/kernel", dir).as_deref(), Some("system_u:object_r:tmp_t:s0"));
        // A path begins with a rule's as text does: /sysvipc with /sys.
        assert_eq!(genfs("/sysvipc/shm", file).as_deref(), Some("system_u:object_r:tmp_t:s0"));
        assert_eq!(genfs("//cpuinfo", file).as_deref(), Some("system_u:object_r:file_t:s0"));
        assert_eq!(p.genfs_context("vfat", "/x", file), None);
    }

    /// `match_wildcard`, as lib/parser.c has it.
    #[test]
    fn a_wildcard_matches_the_whole_text() {
        for (pattern, text, want) in [
            ("/sys*", "/sys/kernel", true),
            ("/sys", "/sys/kernel", false),
            ("/sys/*/x", "/sys/a/b/x", true),
            ("/sys/?", "/sys/a", true),
            ("/sys/?", "/sys/ab", false),
            ("*", "", true),
            ("", "", true),
            ("a*b*c", "aXbYbZc", true),
            ("a*b*c", "aXbYbZ", false),
            ("/proc/*/net*", "/proc/1/net/rpc", true),
        ] {
            assert_eq!(wildcard_matches(pattern.as_bytes(), text.as_bytes()), want, "{pattern} {text}");
        }
    }

    #[test]
    fn a_bitmap_is_sparse() {
        let mut b = Bitmap::default();
        assert!(b.is_empty() && b.len() == 0);
        b.set(3);
        b.set(4_000_000_000);
        assert!(b.get(3) && b.get(4_000_000_000) && !b.get(4));
        assert_eq!((b.count(), b.len(), b.bits().collect::<Vec<_>>()), (2, 4_000_000_001, vec![3, 4_000_000_000]));
        let mut c = Bitmap::default();
        c.set(3);
        assert!(c.within(&b) && !b.within(&c));
    }
}
