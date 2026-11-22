//! The machine's network devices (`struct net_device`): the ones it starts
//! with, `lo` and `eth0` (see [`crate::netlink`]), and the ones made while
//! it runs (a TUN device's, [`crate::tun`]).
//!
//! What a device is, how its flags and MTU change, how a new one is named
//! and numbered, and what is said when it comes, changes and goes, are as
//! Linux 6.18 has them: `net/core/dev.c` (`register_netdevice`,
//! `dev_get_valid_name`, `__dev_alloc_name`, `dev_index_reserve`,
//! `__dev_change_flags`, `netif_get_flags`, `netif_set_mtu_ext`,
//! `unregister_netdevice_many_notify`), `net/core/rtnetlink.c`
//! (`rtnl_fill_ifinfo`, `rtmsg_ifinfo`) and `net/core/net-sysfs.c`. Each
//! change is announced as Linux announces it: an `RTM_NEWLINK` (or
//! `RTM_DELLINK`) to `RTNLGRP_LINK`, and a device's coming and going as
//! uevents of the `net` subsystem.
//!
//! No packet crosses any of these devices: the guest's network is the
//! kernel's own (crate::net), which hands each connection to the host. A
//! device here is its state and what is said of it.
//!
//! Not given in a link message (`rtnl_fill_ifinfo` has them): the GSO, GRO
//! and TSO sizes, `IFLA_XDP`, `IFLA_AF_SPEC` (the per-family settings),
//! `IFLA_MAP` and the empty devlink and DPLL nests. No caller here reads
//! them; one that did would find them missing, not wrong.

use crate::errno::Errno;
use std::sync::Mutex;

pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;
pub const ARPHRD_NONE: u16 = 0xfffe;

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_DEBUG: u32 = 0x4;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_NOTRAILERS: u32 = 0x20;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_NOARP: u32 = 0x80;
pub const IFF_PROMISC: u32 = 0x100;
pub const IFF_ALLMULTI: u32 = 0x200;
pub const IFF_MASTER: u32 = 0x400;
pub const IFF_SLAVE: u32 = 0x800;
pub const IFF_MULTICAST: u32 = 0x1000;
pub const IFF_PORTSEL: u32 = 0x2000;
pub const IFF_AUTOMEDIA: u32 = 0x4000;
pub const IFF_DYNAMIC: u32 = 0x8000;
pub const IFF_LOWER_UP: u32 = 0x10000;
pub const IFF_DORMANT: u32 = 0x20000;
pub const IFF_ECHO: u32 = 0x40000;
/// `IFF_VOLATILE` (`include/uapi/linux/if.h`): what a user's change of
/// flags leaves as it was.
const IFF_VOLATILE: u32 = IFF_LOOPBACK | IFF_POINTOPOINT | IFF_BROADCAST | IFF_ECHO | IFF_MASTER | IFF_SLAVE | IFF_RUNNING | IFF_LOWER_UP | IFF_DORMANT;

/// `IF_OPER_*`.
pub const IF_OPER_UNKNOWN: u8 = 0;
pub const IF_OPER_DOWN: u8 = 2;
pub const IF_OPER_UP: u8 = 6;

/// `IFNAMSIZ`.
pub const IFNAMSIZ: usize = 16;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;

/// What a TUN or TAP device is beyond a device (`struct tun_struct`'s
/// part a guest can see).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunInfo {
    /// TAP (else TUN).
    pub tap: bool,
    /// `tun->flags`: the type and `TUN_FEATURES` (`IFF_NO_PI`, ...), and
    /// `IFF_PERSIST`.
    pub flags: u32,
    pub owner: Option<u32>,
    pub group: Option<u32>,
    /// Descriptors attached (queues).
    pub queues: u32,
}

/// One device.
#[derive(Clone, Debug)]
pub struct NetDev {
    pub index: u32,
    pub name: String,
    /// `ARPHRD_*`.
    pub kind: u16,
    /// `dev->flags`: without `IFF_RUNNING`, `IFF_LOWER_UP` and `IFF_DORMANT`,
    /// which [`NetDev::get_flags`] adds from its state.
    pub flags: u32,
    /// `dev->gflags`: the promiscuous and all-multicast modes a user asked.
    pub gflags: u32,
    pub mtu: u32,
    pub min_mtu: u32,
    /// 0: no limit (`dev_validate_mtu`).
    pub max_mtu: u32,
    pub txqlen: u32,
    /// The hardware address, `addr_len` bytes (none for a TUN device).
    pub addr: Vec<u8>,
    pub broadcast: Vec<u8>,
    /// `addr_assign_type`.
    pub addr_assign_type: u8,
    /// An IPv4 address and its prefix length, the machine's own.
    pub inet: Option<([u8; 4], u8)>,
    pub carrier: bool,
    pub carrier_up: u32,
    pub carrier_down: u32,
    /// `dev->operstate`.
    pub operstate: u8,
    /// `IFLA_QDISC`: `noop` until a device is first up, then its root's.
    pub qdisc: &'static str,
    /// The root queue discipline it takes when first up.
    pub up_qdisc: &'static str,
    pub netns_immutable: bool,
    /// `IFLA_INET6_ADDR_GEN_MODE` (`IN6_ADDR_GEN_MODE_EUI64`, 0, until set).
    pub addr_gen_mode: u8,
    pub tun: Option<TunInfo>,
    /// Packets and bytes in and out, and the drops (`rtnl_link_stats64`'s
    /// first eight).
    pub stats: [u64; 8],
}

impl NetDev {
    /// `netif_running`.
    pub fn running(&self) -> bool {
        self.flags & IFF_UP != 0
    }

    /// `netif_get_flags`: the flags a user sees (`SIOCGIFFLAGS` takes the
    /// low sixteen).
    pub fn get_flags(&self) -> u32 {
        let mut f = (self.flags & !(IFF_PROMISC | IFF_ALLMULTI | IFF_RUNNING | IFF_LOWER_UP | IFF_DORMANT)) | (self.gflags & (IFF_PROMISC | IFF_ALLMULTI));
        if self.running() {
            if matches!(self.operstate, IF_OPER_UP | IF_OPER_UNKNOWN) {
                f |= IFF_RUNNING;
            }
            if self.carrier {
                f |= IFF_LOWER_UP;
            }
        }
        f
    }

    /// `IFLA_OPERSTATE`: down for a device not running, else its own.
    pub fn link_operstate(&self) -> u8 {
        if self.running() { self.operstate } else { IF_OPER_DOWN }
    }

    /// The text sysfs gives `operstate` (`operstates[]`).
    pub fn operstate_text(&self) -> &'static str {
        match self.link_operstate() {
            IF_OPER_UNKNOWN => "unknown",
            1 => "notpresent",
            IF_OPER_DOWN => "down",
            3 => "lowerlayerdown",
            4 => "testing",
            5 => "dormant",
            _ => "up",
        }
    }
}

struct Table {
    devs: Vec<NetDev>,
    /// The last index given (`dev_index_reserve` goes on from it).
    last_index: u32,
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

fn boot_devices() -> Vec<NetDev> {
    vec![
        // drivers/net/loopback.c (`gen_lo_setup`): no queue, no limits on
        // its MTU, its state unknown.
        NetDev {
            index: 1,
            name: "lo".into(),
            kind: ARPHRD_LOOPBACK,
            flags: IFF_UP | IFF_LOOPBACK,
            gflags: 0,
            mtu: 65536,
            min_mtu: 0,
            max_mtu: 0,
            txqlen: 1000,
            addr: vec![0; 6],
            broadcast: vec![0; 6],
            addr_assign_type: 0,
            inet: Some(([127, 0, 0, 1], 8)),
            carrier: true,
            carrier_up: 0,
            carrier_down: 0,
            operstate: IF_OPER_UNKNOWN,
            qdisc: "noqueue",
            up_qdisc: "noqueue",
            netns_immutable: true,
            addr_gen_mode: 0,
            tun: None,
            stats: [0; 8],
        },
        // The network's own interface (crate::netlink): an Ethernet
        // device as `ether_setup` makes one, up, its carrier on.
        NetDev {
            index: 2,
            name: "eth0".into(),
            kind: ARPHRD_ETHER,
            flags: IFF_UP | IFF_BROADCAST | IFF_MULTICAST,
            gflags: 0,
            mtu: 1500,
            min_mtu: 68,
            max_mtu: 1500,
            txqlen: 1000,
            addr: vec![0x02, 0, 0, 0, 0, 0x01],
            broadcast: vec![0xff; 6],
            addr_assign_type: 0,
            inet: Some((crate::netlink::ETH0_ADDR, 24)),
            carrier: true,
            carrier_up: 1,
            carrier_down: 0,
            operstate: IF_OPER_UP,
            qdisc: "pfifo_fast",
            up_qdisc: "pfifo_fast",
            netns_immutable: false,
            addr_gen_mode: 0,
            tun: None,
            stats: [0; 8],
        },
    ]
}

fn with<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    let mut t = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let t = t.get_or_insert_with(|| Table { devs: boot_devices(), last_index: 2 });
    f(t)
}

/// Every device, in the order they were registered.
pub fn all() -> Vec<NetDev> {
    with(|t| t.devs.clone())
}

pub fn by_name(name: &str) -> Option<NetDev> {
    with(|t| t.devs.iter().find(|d| d.name == name).cloned())
}

pub fn by_index(index: u32) -> Option<NetDev> {
    with(|t| t.devs.iter().find(|d| d.index == index).cloned())
}

/// `dev_valid_name`.
pub fn valid_name(name: &str) -> bool {
    !(name.is_empty() || name.len() >= IFNAMSIZ || name == "." || name == ".." || name.bytes().any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace()))
}

/// `dev_prep_valid_name` for a name not yet in use by anything else:
/// valid, and a `%d` template made a name (`__dev_alloc_name`: exactly one
/// `%`, followed by `d`; the lowest free unit below 32768).
fn prep_name(t: &Table, name: &str) -> Result<String, Errno> {
    if !valid_name(name) {
        return Err(Errno::EINVAL);
    }
    if !name.contains('%') {
        if t.devs.iter().any(|d| d.name == name) {
            return Err(Errno::EEXIST);
        }
        return Ok(name.to_string());
    }
    let p = name.find('%').unwrap();
    if name[p + 1..].chars().next() != Some('d') || name[p + 2..].contains('%') {
        return Err(Errno::EINVAL);
    }
    let (head, tail) = (&name[..p], &name[p + 2..]);
    // `8 * PAGE_SIZE` units, as many as a page's bits.
    for unit in 0..8 * 4096u32 {
        let mut cand = format!("{head}{unit}{tail}");
        cand.truncate(IFNAMSIZ - 1);
        if !t.devs.iter().any(|d| d.name == cand) {
            return Ok(cand);
        }
    }
    Err(Errno::ENFILE)
}

/// `register_netdevice`: the device named (a `%d` template filled in) and
/// numbered, its sysfs directory made with its `add` uevent, then listed,
/// then `RTM_NEWLINK` (all changed) to the link group. Its index, or what
/// was wrong with its name (`EINVAL`, `EEXIST`, `ENFILE`) or a fixed index
/// (`EBUSY`).
pub fn register(mut dev: NetDev, fixed_index: Option<u32>) -> Result<NetDev, Errno> {
    let dev = with(|t| {
        dev.name = prep_name(t, &dev.name)?;
        dev.index = match fixed_index {
            Some(i) if t.devs.iter().any(|d| d.index == i) => return Err(Errno::EBUSY),
            Some(i) => i,
            None => {
                // Cyclic from the last given (`xa_alloc_cyclic`), skipping
                // what is in use.
                let mut i = t.last_index;
                loop {
                    i = if i >= i32::MAX as u32 { 1 } else { i + 1 };
                    if !t.devs.iter().any(|d| d.index == i) {
                        break i;
                    }
                }
            }
        };
        if fixed_index.is_none() {
            t.last_index = dev.index;
        }
        Ok(dev.clone())
    })?;
    crate::vfs::sysfs::add_net(&dev.name, dev.index);
    with(|t| t.devs.push(dev.clone()));
    notify(RTM_NEWLINK, &dev, !0);
    Ok(dev)
}

/// `unregister_netdevice`: closed if up (`RTM_NEWLINK` saying `IFF_UP` and
/// `IFF_RUNNING` changed), unlisted, `RTM_DELLINK`, then its sysfs
/// directory goes with its `remove` uevent.
pub fn unregister(index: u32) {
    let Some(mut dev) = by_index(index) else { return };
    if dev.running() {
        with(|t| {
            if let Some(d) = t.devs.iter_mut().find(|d| d.index == index) {
                d.flags &= !IFF_UP;
                dev = d.clone();
            }
        });
        notify(RTM_NEWLINK, &dev, IFF_UP | IFF_RUNNING);
    }
    with(|t| t.devs.retain(|d| d.index != index));
    notify(RTM_DELLINK, &dev, !0);
    crate::vfs::sysfs::remove("net", &dev.name);
}

/// Changes a device's state through `f`, and says nothing.
pub fn update(index: u32, f: impl FnOnce(&mut NetDev)) -> Option<NetDev> {
    with(|t| {
        let d = t.devs.iter_mut().find(|d| d.index == index)?;
        f(d);
        Some(d.clone())
    })
}

/// `netif_change_flags`: the flags a user may set taken from `new`
/// (`__dev_change_flags`), `IFF_UP` by opening or closing it, the
/// promiscuous and all-multicast modes as asked; one `RTM_NEWLINK` with
/// what changed, if anything did.
pub fn change_flags(index: u32, new: u32) -> Result<(), Errno> {
    const USER: u32 = IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP | IFF_DYNAMIC | IFF_MULTICAST | IFF_PORTSEL | IFF_AUTOMEDIA;
    let (dev, changes) = with(|t| {
        let d = t.devs.iter_mut().find(|d| d.index == index).ok_or(Errno::ENODEV)?;
        let (old, old_g) = (d.flags, d.gflags);
        d.flags = (new & USER) | (old & (IFF_UP | IFF_VOLATILE | IFF_PROMISC | IFF_ALLMULTI));
        if (old ^ new) & IFF_UP != 0 {
            if new & IFF_UP != 0 {
                // `__dev_open`: started, and its queue discipline attached
                // (`dev_activate`) the first time.
                d.flags |= IFF_UP;
                d.qdisc = d.up_qdisc;
            } else {
                d.flags &= !IFF_UP;
            }
        }
        d.gflags = (d.gflags & !(IFF_PROMISC | IFF_ALLMULTI)) | (new & (IFF_PROMISC | IFF_ALLMULTI));
        Ok::<_, Errno>((d.clone(), (old ^ d.flags) | (old_g ^ d.gflags)))
    })?;
    if changes != 0 {
        notify(RTM_NEWLINK, &dev, changes);
    }
    Ok(())
}

/// `netif_set_mtu_ext`: the same MTU is nothing; outside the device's
/// range `EINVAL`; else set, and `RTM_NEWLINK` (nothing changed among the
/// flags), up or down.
pub fn set_mtu(index: u32, mtu: i32) -> Result<(), Errno> {
    let dev = with(|t| {
        let d = t.devs.iter_mut().find(|d| d.index == index).ok_or(Errno::ENODEV)?;
        if mtu >= 0 && mtu as u32 == d.mtu {
            return Ok(None);
        }
        if mtu < 0 || (mtu as u32) < d.min_mtu || (d.max_mtu > 0 && mtu as u32 > d.max_mtu) {
            return Err(Errno::EINVAL);
        }
        d.mtu = mtu as u32;
        Ok(Some(d.clone()))
    })?;
    if let Some(dev) = dev {
        notify(RTM_NEWLINK, &dev, 0);
    }
    Ok(())
}

/// `netdev_state_change`: `RTM_NEWLINK` (nothing changed among the
/// flags), only for a device that is up.
pub fn state_change(index: u32) {
    if let Some(dev) = by_index(index).filter(|d| d.running()) {
        notify(RTM_NEWLINK, &dev, 0);
    }
}

/// An `RTM_NEWLINK` (nothing changed among the flags) whether the device
/// is up or not: what a change of its type or address says
/// (`NETDEV_POST_TYPE_CHANGE`, `NETDEV_CHANGEADDR`).
pub fn state_change_any(index: u32) {
    if let Some(dev) = by_index(index) {
        notify(RTM_NEWLINK, &dev, 0);
    }
}

/// `rtmsg_ifinfo`: the device as a link message, from the kernel (port 0,
/// sequence 0, no flags), to `RTNLGRP_LINK`.
fn notify(kind: u16, dev: &NetDev, change: u32) {
    let body = fill(dev, change);
    let mut msg = Vec::with_capacity(16 + body.len());
    msg.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    msg.extend_from_slice(&kind.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&body);
    const RTNLGRP_LINK: u32 = 1;
    crate::netlink::route_notify(msg, RTNLGRP_LINK);
}

fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// A nest of attributes made by `f`.
fn nest(out: &mut Vec<u8>, kind: u16, f: impl FnOnce(&mut Vec<u8>)) {
    let mut inner = Vec::new();
    f(&mut inner);
    attr(out, kind, &inner);
}

/// `IFLA_PAD` so that the next attribute's payload is 8-byte aligned in
/// the message (`nla_put_64bit`): the body starts 16 bytes in.
fn pad64(out: &mut Vec<u8>) {
    const IFLA_PAD: u16 = 42;
    if (16 + out.len() + 4) % 8 != 0 {
        attr(out, IFLA_PAD, &[]);
    }
}

/// `rtnl_fill_ifinfo`'s body: `struct ifinfomsg` and the attributes, in
/// its order (those this kernel gives; see the module's notes).
pub fn fill(dev: &NetDev, change: u32) -> Vec<u8> {
    const IFLA_ADDRESS: u16 = 1;
    const IFLA_BROADCAST: u16 = 2;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_MTU: u16 = 4;
    const IFLA_QDISC: u16 = 6;
    const IFLA_STATS: u16 = 7;
    const IFLA_TXQLEN: u16 = 13;
    const IFLA_OPERSTATE: u16 = 16;
    const IFLA_LINKMODE: u16 = 17;
    const IFLA_LINKINFO: u16 = 18;
    const IFLA_STATS64: u16 = 23;
    const IFLA_GROUP: u16 = 27;
    const IFLA_PROMISCUITY: u16 = 30;
    const IFLA_NUM_TX_QUEUES: u16 = 31;
    const IFLA_NUM_RX_QUEUES: u16 = 32;
    const IFLA_CARRIER: u16 = 33;
    const IFLA_CARRIER_CHANGES: u16 = 35;
    const IFLA_PROTO_DOWN: u16 = 39;
    const IFLA_CARRIER_UP_COUNT: u16 = 47;
    const IFLA_CARRIER_DOWN_COUNT: u16 = 48;
    const IFLA_MIN_MTU: u16 = 50;
    const IFLA_MAX_MTU: u16 = 51;
    const IFLA_ALLMULTI: u16 = 61;
    const IFLA_NETNS_IMMUTABLE: u16 = 67;
    const IFLA_INFO_KIND: u16 = 1;
    const IFLA_INFO_DATA: u16 = 2;
    const IFLA_TUN_OWNER: u16 = 1;
    const IFLA_TUN_GROUP: u16 = 2;
    const IFLA_TUN_TYPE: u16 = 3;
    const IFLA_TUN_PI: u16 = 4;
    const IFLA_TUN_VNET_HDR: u16 = 5;
    const IFLA_TUN_PERSIST: u16 = 6;
    const IFLA_TUN_MULTI_QUEUE: u16 = 7;
    let mut b = vec![0u8, 0]; // AF_UNSPEC, pad
    b.extend_from_slice(&dev.kind.to_le_bytes());
    b.extend_from_slice(&(dev.index as i32).to_le_bytes());
    b.extend_from_slice(&dev.get_flags().to_le_bytes());
    b.extend_from_slice(&change.to_le_bytes());
    let mut name = dev.name.clone().into_bytes();
    name.push(0);
    attr(&mut b, IFLA_IFNAME, &name);
    attr(&mut b, IFLA_TXQLEN, &dev.txqlen.to_le_bytes());
    attr(&mut b, IFLA_OPERSTATE, &[dev.link_operstate()]);
    attr(&mut b, IFLA_LINKMODE, &[0]);
    attr(&mut b, IFLA_NETNS_IMMUTABLE, &[dev.netns_immutable as u8]);
    attr(&mut b, IFLA_MTU, &dev.mtu.to_le_bytes());
    attr(&mut b, IFLA_MIN_MTU, &dev.min_mtu.to_le_bytes());
    attr(&mut b, IFLA_MAX_MTU, &dev.max_mtu.to_le_bytes());
    attr(&mut b, IFLA_GROUP, &0u32.to_le_bytes());
    attr(&mut b, IFLA_PROMISCUITY, &((dev.gflags & IFF_PROMISC != 0) as u32).to_le_bytes());
    attr(&mut b, IFLA_ALLMULTI, &((dev.gflags & IFF_ALLMULTI != 0) as u32).to_le_bytes());
    attr(&mut b, IFLA_NUM_TX_QUEUES, &1u32.to_le_bytes());
    attr(&mut b, IFLA_NUM_RX_QUEUES, &1u32.to_le_bytes());
    attr(&mut b, IFLA_CARRIER, &[dev.carrier as u8]);
    attr(&mut b, IFLA_CARRIER_CHANGES, &(dev.carrier_up + dev.carrier_down).to_le_bytes());
    attr(&mut b, IFLA_CARRIER_UP_COUNT, &dev.carrier_up.to_le_bytes());
    attr(&mut b, IFLA_CARRIER_DOWN_COUNT, &dev.carrier_down.to_le_bytes());
    attr(&mut b, IFLA_PROTO_DOWN, &[0]);
    if !dev.addr.is_empty() {
        attr(&mut b, IFLA_ADDRESS, &dev.addr);
        attr(&mut b, IFLA_BROADCAST, &dev.broadcast);
    }
    // `struct rtnl_link_stats64` (24 counters), then its 32-bit copy.
    let mut s64 = Vec::with_capacity(24 * 8);
    for i in 0..24 {
        s64.extend_from_slice(&dev.stats.get(i).copied().unwrap_or(0).to_le_bytes());
    }
    pad64(&mut b);
    attr(&mut b, IFLA_STATS64, &s64);
    let mut s32 = Vec::with_capacity(24 * 4);
    for i in 0..24 {
        s32.extend_from_slice(&(dev.stats.get(i).copied().unwrap_or(0) as u32).to_le_bytes());
    }
    attr(&mut b, IFLA_STATS, &s32);
    if let Some(tun) = &dev.tun {
        // `tun_fill_info`: kind "tun" for TAP too.
        nest(&mut b, IFLA_LINKINFO, |l| {
            attr(l, IFLA_INFO_KIND, b"tun\0");
            nest(l, IFLA_INFO_DATA, |d| {
                attr(d, IFLA_TUN_TYPE, &[if tun.tap { 2 } else { 1 }]);
                if let Some(o) = tun.owner {
                    attr(d, IFLA_TUN_OWNER, &o.to_le_bytes());
                }
                if let Some(g) = tun.group {
                    attr(d, IFLA_TUN_GROUP, &g.to_le_bytes());
                }
                attr(d, IFLA_TUN_PI, &[(tun.flags & crate::tun::IFF_NO_PI == 0) as u8]);
                attr(d, IFLA_TUN_VNET_HDR, &[(tun.flags & crate::tun::IFF_VNET_HDR != 0) as u8]);
                attr(d, IFLA_TUN_PERSIST, &[(tun.flags & crate::tun::IFF_PERSIST != 0) as u8]);
                attr(d, IFLA_TUN_MULTI_QUEUE, &[(tun.flags & crate::tun::IFF_MULTI_QUEUE != 0) as u8]);
            });
        });
    }
    let mut q = dev.qdisc.as_bytes().to_vec();
    q.push(0);
    attr(&mut b, IFLA_QDISC, &q);
    b
}

/// `do_setlink` for an `RTM_NEWLINK` request naming a device that is
/// there: `ifinfomsg` flags with their change mask, `IFLA_MTU`, and
/// `IFLA_AF_SPEC`'s IPv6 address-generation mode. Anything else it names
/// is refused, said once.
pub fn setlink(index: u32, flags: u32, change: u32, attrs: &[u8]) -> Result<(), Errno> {
    const IFLA_IFNAME: u16 = 3;
    const IFLA_MTU: u16 = 4;
    const IFLA_AF_SPEC: u16 = 26;
    const AF_INET6: u16 = 10;
    const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
    let dev = by_index(index).ok_or(Errno::ENODEV)?;
    let mut mtu = None;
    let mut gen_mode = None;
    for (kind, data) in attrs_of(attrs) {
        match kind {
            IFLA_IFNAME => {
                let n = data.split(|&b| b == 0).next().unwrap_or(&[]);
                if n != dev.name.as_bytes() {
                    crate::bpf::say_once("RTM_NEWLINK renaming a device (not here)");
                    return Err(Errno::EOPNOTSUPP);
                }
            }
            IFLA_MTU if data.len() >= 4 => mtu = Some(u32::from_le_bytes(data[..4].try_into().unwrap())),
            IFLA_MTU => return Err(Errno::EINVAL),
            IFLA_AF_SPEC => {
                for (fam, fdata) in attrs_of(data) {
                    if fam != AF_INET6 {
                        crate::bpf::say_once(&format!("RTM_NEWLINK IFLA_AF_SPEC for family {fam} (only IPv6's address generation mode here)"));
                        return Err(Errno::EOPNOTSUPP);
                    }
                    // `inet6_validate_link_af`: the mode or a token is
                    // needed; a mode past the last is EINVAL.
                    let mut any = false;
                    for (k, v) in attrs_of(fdata) {
                        match k {
                            IFLA_INET6_ADDR_GEN_MODE => {
                                let m = *v.first().ok_or(Errno::EINVAL)?;
                                if m > 3 {
                                    return Err(Errno::EINVAL);
                                }
                                gen_mode = Some(m);
                                any = true;
                            }
                            _ => {
                                crate::bpf::say_once(&format!("RTM_NEWLINK IPv6 link attribute {k} (only the address generation mode here)"));
                                return Err(Errno::EOPNOTSUPP);
                            }
                        }
                    }
                    if !any {
                        return Err(Errno::EINVAL);
                    }
                    // A device without IPv6 state (an MTU below 1280).
                    if dev.mtu < 1280 {
                        return Err(Errno::EAFNOSUPPORT);
                    }
                }
            }
            _ => {
                crate::bpf::say_once(&format!("RTM_NEWLINK attribute {kind} (not here)"));
                return Err(Errno::EOPNOTSUPP);
            }
        }
    }
    if let Some(m) = mtu {
        set_mtu(index, m as i32)?;
    }
    if flags != 0 || change != 0 {
        // `rtnl_dev_combine_flags`.
        let cur = by_index(index).ok_or(Errno::ENODEV)?;
        let mut f = flags;
        if change != 0 {
            f = (f & change) | (cur.get_flags() & !change);
        }
        change_flags(index, f)?;
    }
    if let Some(m) = gen_mode {
        update(index, |d| d.addr_gen_mode = m);
        state_change(index);
    }
    Ok(())
}

/// The attributes in `data`: kind (without the nested and byte-order
/// bits) and payload.
pub fn attrs_of(data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= data.len() {
        let len = u16::from_le_bytes([data[at], data[at + 1]]) as usize;
        let kind = u16::from_le_bytes([data[at + 2], data[at + 3]]) & 0x3fff;
        if len < 4 || at + len > data.len() {
            break;
        }
        out.push((kind, &data[at + 4..at + len]));
        at += (len + 3) & !3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked_and_templates_filled() {
        assert!(valid_name("thread-wpan"));
        for bad in ["", ".", "..", "a/b", "a:b", "a b", "0123456789abcdef"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        let t = Table { devs: boot_devices(), last_index: 2 };
        assert_eq!(prep_name(&t, "tun%d"), Ok("tun0".into()));
        assert_eq!(prep_name(&t, "eth%d"), Ok("eth1".into()));
        assert_eq!(prep_name(&t, "lo"), Err(Errno::EEXIST));
        assert_eq!(prep_name(&t, "a%s"), Err(Errno::EINVAL));
        assert_eq!(prep_name(&t, "a%d%d"), Err(Errno::EINVAL));
    }

    #[test]
    fn flags_a_user_sees() {
        let mut d = boot_devices().remove(0);
        // lo up: running (its state unknown) and its carrier on.
        assert_eq!(d.get_flags(), IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP);
        d.flags &= !IFF_UP;
        assert_eq!(d.get_flags(), IFF_LOOPBACK);
        assert_eq!(d.link_operstate(), IF_OPER_DOWN);
    }
}
