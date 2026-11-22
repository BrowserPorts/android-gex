//! TUN and TAP devices: `/dev/net/tun` (misc 10:200, Android's `/dev/tun`),
//! after Linux 6.18's `drivers/net/tun.c`.
//!
//! A descriptor of the misc device becomes a device's queue at
//! `TUNSETIFF`: a new device it makes (with `CAP_NET_ADMIN`), or an
//! existing one it attaches to. The device is a network device of the
//! machine's ([`crate::netdev`]): it is listed, announced and changed as
//! any other, and goes with its last queue unless it was made persistent.
//! Android's Thread network service makes one (`thread-wpan`) in the system
//! server, which dies without it.
//!
//! No packet reaches these devices or leaves them: the guest's network is
//! the kernel's own and goes to the host by connection (crate::net), with
//! no routes to a device here. So a read finds nothing (it waits, or is
//! `EAGAIN`), and a packet written is checked as Linux checks it, counted,
//! and goes nowhere (said once). The MLD reports Linux would send out of an
//! up device when a group is joined on it are not sent either.
//!
//! Not here, and said when asked: multiqueue's `TUNSETQUEUE`, the network
//! namespace ioctls (`SIOCGSKNS`, `TUNGETDEVNETNS`), classic and eBPF
//! filters and steering. An offload change is kept but announces no
//! feature change.

use crate::errno::{Errno, SysResult};
use crate::netdev::{self, NetDev, TunInfo};
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::sync::{Arc, Mutex};

pub const MISC_MINOR: u32 = 200;

pub const IFF_TUN: u32 = 0x0001;
pub const IFF_TAP: u32 = 0x0002;
pub const IFF_NAPI: u32 = 0x0010;
pub const IFF_NAPI_FRAGS: u32 = 0x0020;
pub const IFF_NO_CARRIER: u32 = 0x0040;
pub const IFF_MULTI_QUEUE: u32 = 0x0100;
pub const IFF_ATTACH_QUEUE: u32 = 0x0200;
pub const IFF_DETACH_QUEUE: u32 = 0x0400;
pub const IFF_PERSIST: u32 = 0x0800;
pub const IFF_NO_PI: u32 = 0x1000;
pub const IFF_NOFILTER: u32 = 0x1000;
pub const IFF_ONE_QUEUE: u32 = 0x2000;
pub const IFF_VNET_HDR: u32 = 0x4000;
pub const IFF_TUN_EXCL: u32 = 0x8000;
/// `TUN_FEATURES`: what of `TUNSETIFF`'s flags a device keeps.
pub const TUN_FEATURES: u32 = IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR | IFF_MULTI_QUEUE | IFF_NAPI | IFF_NAPI_FRAGS;
/// `TUN_VNET_LE`, kept in the flags' top bit.
const TUN_VNET_LE: u32 = 0x8000_0000;
/// `MAX_TAP_QUEUES`.
const MAX_QUEUES: u32 = 256;

pub mod ioctl {
    pub const TUNSETNOCSUM: u64 = 0x4004_54c8;
    pub const TUNSETDEBUG: u64 = 0x4004_54c9;
    pub const TUNSETIFF: u64 = 0x4004_54ca;
    pub const TUNSETPERSIST: u64 = 0x4004_54cb;
    pub const TUNSETOWNER: u64 = 0x4004_54cc;
    pub const TUNSETLINK: u64 = 0x4004_54cd;
    pub const TUNSETGROUP: u64 = 0x4004_54ce;
    pub const TUNGETFEATURES: u64 = 0x8004_54cf;
    pub const TUNSETOFFLOAD: u64 = 0x4004_54d0;
    pub const TUNSETTXFILTER: u64 = 0x4004_54d1;
    pub const TUNGETIFF: u64 = 0x8004_54d2;
    pub const TUNGETSNDBUF: u64 = 0x8004_54d3;
    pub const TUNSETSNDBUF: u64 = 0x4004_54d4;
    pub const TUNATTACHFILTER: u64 = 0x4010_54d5;
    pub const TUNDETACHFILTER: u64 = 0x4010_54d6;
    pub const TUNGETVNETHDRSZ: u64 = 0x8004_54d7;
    pub const TUNSETVNETHDRSZ: u64 = 0x4004_54d8;
    pub const TUNSETQUEUE: u64 = 0x4004_54d9;
    pub const TUNSETIFINDEX: u64 = 0x4004_54da;
    pub const TUNGETFILTER: u64 = 0x8010_54db;
    pub const TUNSETVNETLE: u64 = 0x4004_54dc;
    pub const TUNGETVNETLE: u64 = 0x8004_54dd;
    pub const TUNSETVNETBE: u64 = 0x4004_54de;
    pub const TUNGETVNETBE: u64 = 0x8004_54df;
    pub const TUNSETSTEERINGEBPF: u64 = 0x8004_54e0;
    pub const TUNSETFILTEREBPF: u64 = 0x8004_54e1;
    pub const TUNSETCARRIER: u64 = 0x4004_54e2;
    pub const TUNGETDEVNETNS: u64 = 0x0000_54e3;
    pub const SIOCGSKNS: u64 = 0x894c;
    pub const SIOCSIFHWADDR: u64 = 0x8924;
    pub const SIOCGIFHWADDR: u64 = 0x8927;
}

/// Who asks (`tun_not_capable`, the create's capability check).
pub struct Caller<'a> {
    pub net_admin: bool,
    pub euid: u32,
    pub in_group: &'a dyn Fn(u32) -> bool,
}

/// One open of the misc device (`struct tun_file`).
pub struct TunFile {
    st: Mutex<State>,
    queue: crate::wait::Queue,
    node: Option<crate::vfs::devices::NodeMeta>,
}

#[derive(Debug)]
struct State {
    /// The device it is a queue of (`tfile->tun`), by index.
    dev: Option<u32>,
    /// `TUNSETIFINDEX`: the index a device it makes will have.
    ifindex: Option<u32>,
    /// `sk_sndbuf`.
    sndbuf: i32,
    vnet_hdr_sz: i32,
}

impl TunFile {
    pub fn open(node: Option<crate::vfs::devices::NodeMeta>) -> Arc<dyn FileHandle> {
        Arc::new(TunFile { st: Mutex::new(State { dev: None, ifindex: None, sndbuf: i32::MAX, vnet_hdr_sz: 10 }), queue: crate::wait::Queue::new(), node })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The device this is a queue of, if it still is one (it may have been
    /// deleted under it, `tun_detach_all`).
    fn attached(&self) -> Option<NetDev> {
        let index = self.lock().dev?;
        let d = netdev::by_index(index).filter(|d| d.tun.is_some());
        if d.is_none() {
            self.lock().dev = None;
        }
        d
    }

    /// `__tun_chr_ioctl`.
    pub fn ioctl(&self, cx: &Caller<'_>, m: &mut GuestMem<'_>, req: u64, arg: u64) -> SysResult {
        use ioctl::*;
        // An ifreq is read first for these, and `EFAULT` for any of them
        // whose argument cannot be read.
        let mut ifr = [0u8; 40];
        if req == TUNSETIFF || req == TUNSETQUEUE || ((req >> 8) & 0xff == 0x89 && req != SIOCGSKNS) {
            ifr.copy_from_slice(m.read(arg, 40)?);
        }
        match req {
            TUNGETFEATURES => {
                m.write_u32(arg, IFF_TUN | IFF_TAP | IFF_NO_CARRIER | TUN_FEATURES)?;
                return Ok(0);
            }
            TUNSETQUEUE => {
                if self.attached().is_some_and(|d| d.tun.as_ref().is_some_and(|t| t.flags & IFF_MULTI_QUEUE != 0)) {
                    crate::bpf::say_once("TUNSETQUEUE (a multiqueue device's queues detached and attached again: not here)");
                    return Err(Errno::EOPNOTSUPP);
                }
                return Err(Errno::EINVAL);
            }
            SIOCGSKNS => {
                crate::bpf::say_once("SIOCGSKNS on a TUN descriptor (network namespaces: not here)");
                return Err(Errno::EOPNOTSUPP);
            }
            TUNSETIFF => {
                if self.attached().is_some() {
                    return Err(Errno::EEXIST);
                }
                ifr[15] = 0;
                let name = ifr[..16].split(|&b| b == 0).next().unwrap_or(&[]);
                let name = std::str::from_utf8(name).map_err(|_| Errno::EINVAL)?.to_string();
                let flags = u16::from_le_bytes([ifr[16], ifr[17]]) as u32;
                let index = self.set_iff(cx, &name, flags)?;
                let dev = netdev::by_index(index).ok_or(Errno::ENODEV)?;
                ifr[..16].fill(0);
                ifr[..dev.name.len()].copy_from_slice(dev.name.as_bytes());
                m.write(arg, &ifr)?;
                return Ok(0);
            }
            TUNSETIFINDEX => {
                if self.attached().is_some() {
                    return Err(Errno::EPERM);
                }
                let i = m.read_u32(arg)? as i32;
                if i < 0 {
                    return Err(Errno::EINVAL);
                }
                self.lock().ifindex = (i != 0).then_some(i as u32);
                return Ok(0);
            }
            _ => {}
        }
        let Some(dev) = self.attached() else { return Err(Errno::EBADFD) };
        let tun = dev.tun.clone().unwrap();
        let index = dev.index;
        match req {
            TUNGETIFF => {
                let mut out = [0u8; 40];
                out[..dev.name.len()].copy_from_slice(dev.name.as_bytes());
                // `tun_flags`, and no classic filter attached: `IFF_NOFILTER`.
                let f = (tun.flags & (TUN_FEATURES | IFF_PERSIST | IFF_TUN | IFF_TAP)) | IFF_NOFILTER;
                out[16..18].copy_from_slice(&(f as u16).to_le_bytes());
                m.write(arg, &out)?;
                Ok(0)
            }
            TUNSETNOCSUM | TUNSETDEBUG => Ok(0),
            TUNSETPERSIST => {
                let on = arg != 0;
                let changed = (tun.flags & IFF_PERSIST != 0) != on;
                netdev::update(index, |d| {
                    if let Some(t) = d.tun.as_mut() {
                        if on { t.flags |= IFF_PERSIST } else { t.flags &= !IFF_PERSIST }
                    }
                });
                if changed {
                    netdev::state_change(index);
                }
                Ok(0)
            }
            TUNSETOWNER | TUNSETGROUP => {
                let id = arg as u32;
                if id == u32::MAX {
                    return Err(Errno::EINVAL);
                }
                netdev::update(index, |d| {
                    if let Some(t) = d.tun.as_mut() {
                        if req == TUNSETOWNER { t.owner = Some(id) } else { t.group = Some(id) }
                    }
                });
                netdev::state_change(index);
                Ok(0)
            }
            TUNSETLINK => {
                if dev.running() {
                    return Err(Errno::EBUSY);
                }
                let kind = arg as u16;
                // `tun_get_addr_len`: the hardware address's length for the
                // type; those this kernel knows, said for any other.
                let len = match kind {
                    netdev::ARPHRD_ETHER => 6,
                    netdev::ARPHRD_NONE | netdev::ARPHRD_LOOPBACK => 0,
                    _ => {
                        crate::bpf::say_once(&format!("TUNSETLINK to link type {kind} (its hardware address's length is not known here; taken as none)"));
                        0
                    }
                };
                let d = netdev::update(index, |d| {
                    d.kind = kind;
                    d.addr.resize(len, 0);
                    d.broadcast.resize(len, if len > 0 { 0xff } else { 0 });
                });
                // `NETDEV_POST_TYPE_CHANGE`: announced up or down.
                if d.is_some() {
                    netdev::state_change_any(index);
                }
                Ok(0)
            }
            TUNSETOFFLOAD => {
                const CSUM: u64 = 0x01;
                const TSO4: u64 = 0x02;
                const TSO6: u64 = 0x04;
                const TSO_ECN: u64 = 0x08;
                const UFO: u64 = 0x10;
                const USO4: u64 = 0x20;
                const USO6: u64 = 0x40;
                const UDP_TUNNEL_GSO: u64 = 0x80;
                const UDP_TUNNEL_GSO_CSUM: u64 = 0x100;
                let mut a = arg;
                if a & CSUM != 0 {
                    a &= !CSUM;
                    let mut plain = false;
                    if a & (TSO4 | TSO6) != 0 {
                        a &= !(TSO4 | TSO6 | TSO_ECN);
                        plain = true;
                    }
                    a &= !UFO;
                    if a & USO4 != 0 && a & USO6 != 0 {
                        a &= !(USO4 | USO6);
                        plain = true;
                    }
                    if plain && a & UDP_TUNNEL_GSO != 0 {
                        a &= !(UDP_TUNNEL_GSO | UDP_TUNNEL_GSO_CSUM);
                    }
                }
                if a != 0 {
                    return Err(Errno::EINVAL);
                }
                Ok(0)
            }
            TUNSETTXFILTER | TUNATTACHFILTER | TUNDETACHFILTER | TUNGETFILTER => {
                if !tun.tap {
                    return Err(Errno::EINVAL);
                }
                crate::bpf::say_once("a TAP device's filters (not here)");
                Err(Errno::EOPNOTSUPP)
            }
            TUNGETSNDBUF => {
                m.write_u32(arg, self.lock().sndbuf as u32)?;
                Ok(0)
            }
            TUNSETSNDBUF => {
                let v = m.read_u32(arg)? as i32;
                if v <= 0 {
                    return Err(Errno::EINVAL);
                }
                self.lock().sndbuf = v;
                Ok(0)
            }
            TUNGETVNETHDRSZ => {
                m.write_u32(arg, self.lock().vnet_hdr_sz as u32)?;
                Ok(0)
            }
            TUNSETVNETHDRSZ => {
                let v = m.read_u32(arg)? as i32;
                if v < 10 {
                    return Err(Errno::EINVAL);
                }
                self.lock().vnet_hdr_sz = v;
                Ok(0)
            }
            TUNSETVNETLE => {
                let on = m.read_u32(arg)? != 0;
                netdev::update(index, |d| {
                    if let Some(t) = d.tun.as_mut() {
                        if on { t.flags |= TUN_VNET_LE } else { t.flags &= !TUN_VNET_LE }
                    }
                });
                Ok(0)
            }
            TUNGETVNETLE => {
                m.write_u32(arg, (tun.flags & TUN_VNET_LE != 0) as u32)?;
                Ok(0)
            }
            // No cross-endian virtio headers in GKI.
            TUNSETVNETBE | TUNGETVNETBE => Err(Errno::EINVAL),
            TUNSETSTEERINGEBPF | TUNSETFILTEREBPF => {
                if m.read_u32(arg)? as i32 == -1 {
                    return Ok(0);
                }
                crate::bpf::say_once("a TUN device's eBPF steering or filter program (not here)");
                Err(Errno::EOPNOTSUPP)
            }
            TUNSETCARRIER => {
                let on = m.read_u32(arg)? != 0;
                set_carrier(index, on);
                Ok(0)
            }
            TUNGETDEVNETNS => {
                crate::bpf::say_once("TUNGETDEVNETNS (network namespaces: not here)");
                Err(Errno::EOPNOTSUPP)
            }
            SIOCGIFHWADDR => {
                let mut out = ifr;
                out[16..32].fill(0);
                out[16..18].copy_from_slice(&dev.kind.to_le_bytes());
                out[18..18 + dev.addr.len().min(14)].copy_from_slice(&dev.addr[..dev.addr.len().min(14)]);
                m.write(arg, &out)?;
                Ok(0)
            }
            SIOCSIFHWADDR => {
                if !tun.tap {
                    return Err(Errno::EOPNOTSUPP);
                }
                if u16::from_le_bytes([ifr[16], ifr[17]]) != dev.kind {
                    return Err(Errno::EINVAL);
                }
                let mac = ifr[18..24].to_vec();
                // `eth_mac_addr`: a valid unicast address.
                if mac.iter().all(|&b| b == 0) || mac[0] & 1 != 0 {
                    return Err(Errno::EADDRNOTAVAIL);
                }
                netdev::update(index, |d| {
                    d.addr = mac;
                    d.addr_assign_type = 3; // NET_ADDR_SET
                });
                netdev::state_change_any(index);
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `tun_set_iff`: attach to the device named, or make it. Its index.
    fn set_iff(&self, cx: &Caller<'_>, name: &str, flags: u32) -> Result<u32, Errno> {
        if flags & IFF_NAPI_FRAGS != 0 {
            if !cx.net_admin {
                return Err(Errno::EPERM);
            }
            if flags & IFF_NAPI == 0 || flags & IFF_TAP == 0 || flags & IFF_TUN != 0 {
                return Err(Errno::EINVAL);
            }
        }
        if let Some(dev) = (!name.is_empty()).then(|| netdev::by_name(name)).flatten() {
            if flags & IFF_TUN_EXCL != 0 {
                return Err(Errno::EBUSY);
            }
            let Some(tun) = dev.tun.clone() else { return Err(Errno::EINVAL) };
            let want_tap = flags & IFF_TUN == 0 && flags & IFF_TAP != 0;
            if want_tap != tun.tap || (flags & IFF_TUN == 0 && flags & IFF_TAP == 0) {
                return Err(Errno::EINVAL);
            }
            if (flags & IFF_MULTI_QUEUE != 0) != (tun.flags & IFF_MULTI_QUEUE != 0) {
                return Err(Errno::EINVAL);
            }
            // `tun_not_capable`.
            let owner_bars = tun.owner.is_some_and(|o| o != cx.euid);
            let group_bars = tun.group.is_some_and(|g| !(cx.in_group)(g));
            if (owner_bars || group_bars) && !cx.net_admin {
                return Err(Errno::EPERM);
            }
            // `tun_attach`.
            if tun.flags & IFF_MULTI_QUEUE == 0 && tun.queues > 0 {
                return Err(Errno::EBUSY);
            }
            if tun.queues >= MAX_QUEUES {
                return Err(Errno::E2BIG);
            }
            let was_off = !dev.carrier;
            netdev::update(dev.index, |d| {
                if let Some(t) = d.tun.as_mut() {
                    t.queues += 1;
                    t.flags = (t.flags & !TUN_FEATURES) | (flags & TUN_FEATURES);
                }
            });
            self.lock().dev = Some(dev.index);
            netdev::state_change(dev.index);
            if flags & IFF_NO_CARRIER != 0 {
                set_carrier(dev.index, false);
            } else if was_off {
                set_carrier(dev.index, true);
            }
            return Ok(dev.index);
        }
        if !cx.net_admin {
            return Err(Errno::EPERM);
        }
        let tap = if flags & IFF_TUN != 0 {
            false
        } else if flags & IFF_TAP != 0 {
            true
        } else {
            return Err(Errno::EINVAL);
        };
        let name = if name.is_empty() { if tap { "tap%d" } else { "tun%d" }.to_string() } else { name.to_string() };
        let carrier = flags & IFF_NO_CARRIER == 0;
        let tun = TunInfo { tap, flags: (if tap { IFF_TAP } else { IFF_TUN }) | (flags & TUN_FEATURES), owner: None, group: None, queues: 1 };
        let dev = if tap {
            // `ether_setup`, a random address (`eth_hw_addr_random`).
            let mut mac = [0u8; 6];
            crate::vfs::devfs::fill_random(&mut mac);
            mac[0] = (mac[0] & 0xfe) | 0x02;
            NetDev {
                index: 0,
                name,
                kind: netdev::ARPHRD_ETHER,
                flags: netdev::IFF_BROADCAST | netdev::IFF_MULTICAST,
                gflags: 0,
                mtu: 1500,
                min_mtu: 68,
                max_mtu: 65521,
                txqlen: 1000,
                addr: mac.to_vec(),
                broadcast: vec![0xff; 6],
                addr_assign_type: 1,
                inet: None,
                carrier,
                carrier_up: 0,
                carrier_down: 0,
                operstate: if carrier { netdev::IF_OPER_UNKNOWN } else { netdev::IF_OPER_DOWN },
                qdisc: "noop",
                up_qdisc: "pfifo_fast",
                netns_immutable: false,
                addr_gen_mode: 0,
                tun: Some(tun),
                stats: [0; 8],
            }
        } else {
            NetDev {
                index: 0,
                name,
                kind: netdev::ARPHRD_NONE,
                flags: netdev::IFF_POINTOPOINT | netdev::IFF_NOARP | netdev::IFF_MULTICAST,
                gflags: 0,
                mtu: 1500,
                min_mtu: 68,
                max_mtu: 65535,
                txqlen: 500,
                addr: Vec::new(),
                broadcast: Vec::new(),
                addr_assign_type: 0,
                inet: None,
                carrier,
                carrier_up: 0,
                carrier_down: 0,
                operstate: if carrier { netdev::IF_OPER_UNKNOWN } else { netdev::IF_OPER_DOWN },
                qdisc: "noop",
                up_qdisc: "pfifo_fast",
                netns_immutable: false,
                addr_gen_mode: 0,
                tun: Some(tun),
                stats: [0; 8],
            }
        };
        let fixed = self.lock().ifindex;
        let dev = netdev::register(dev, fixed)?;
        self.lock().dev = Some(dev.index);
        Ok(dev.index)
    }

    /// `tun_detach`: the last queue of a device that is not persistent
    /// takes it with it; a persistent one loses its carrier.
    fn detach(&self) {
        let Some(index) = self.lock().dev.take() else { return };
        let Some(dev) = netdev::update(index, |d| {
            if let Some(t) = d.tun.as_mut() {
                t.queues = t.queues.saturating_sub(1);
            }
        }) else {
            return;
        };
        let Some(tun) = dev.tun else { return };
        if tun.queues == 0 {
            if tun.flags & IFF_PERSIST == 0 {
                // The carrier's loss is linkwatch's to announce, later; by
                // then the device is closed and gone, and nothing is said
                // of it but the closing and the deletion.
                netdev::update(index, |d| {
                    if d.carrier {
                        d.carrier = false;
                        d.carrier_down += 1;
                        d.operstate = netdev::IF_OPER_DOWN;
                    }
                });
                netdev::unregister(index);
                return;
            }
            set_carrier(index, false);
        }
        netdev::state_change(index);
    }
}

/// `netif_carrier_on`/`off` and what linkwatch then makes of it: the
/// state up or down, counted, and announced when the device is up.
fn set_carrier(index: u32, on: bool) {
    let Some(old) = netdev::by_index(index) else { return };
    if old.carrier == on {
        return;
    }
    netdev::update(index, |d| {
        d.carrier = on;
        if on {
            d.carrier_up += 1;
            d.operstate = netdev::IF_OPER_UP;
        } else {
            d.carrier_down += 1;
            d.operstate = netdev::IF_OPER_DOWN;
        }
    });
    netdev::state_change(index);
}

impl std::fmt::Debug for TunFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunFile").field("st", &self.st).finish()
    }
}

impl Drop for TunFile {
    fn drop(&mut self) {
        self.detach();
    }
}

impl FileHandle for TunFile {
    /// `tun_do_read`: one packet a read. None ever comes here (see the
    /// module's notes): `EAGAIN`, which a blocking read waits on.
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if self.attached().is_none() {
            return Err(Errno::EBADFD);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        Err(Errno::EAGAIN)
    }

    /// `tun_get_user`: with no packet information, the IP version must be
    /// 4 or 6 (`EINVAL`), then the device must be up (`EIO`); taken whole.
    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        let Some(dev) = self.attached() else { return Err(Errno::EBADFD) };
        let tun = dev.tun.clone().unwrap();
        let drop_it = |e: Errno| {
            netdev::update(dev.index, |d| d.stats[5] += 1); // rx_dropped
            Err(e)
        };
        let payload = if tun.flags & IFF_NO_PI == 0 {
            if buf.len() < 4 {
                return drop_it(Errno::EINVAL);
            }
            &buf[4..]
        } else {
            buf
        };
        if !tun.tap && tun.flags & IFF_NO_PI != 0 {
            let version = payload.first().map_or(0, |b| b >> 4);
            if version != 4 && version != 6 {
                return drop_it(Errno::EINVAL);
            }
        }
        if !dev.running() {
            return drop_it(Errno::EIO);
        }
        crate::bpf::say_once("a packet written to a TUN or TAP device (no route leads anywhere from one here: counted and dropped)");
        netdev::update(dev.index, |d| {
            d.stats[0] += 1; // rx_packets
            d.stats[2] += buf.len() as u64; // rx_bytes
        });
        Ok(buf.len() as u64)
    }

    fn keeps_records(&self) -> bool {
        true
    }

    /// Whether a read returns now: detached (its `EBADFD`); never with a
    /// device, whose queue stays empty.
    fn poll_readable(&self) -> bool {
        self.attached().is_none()
    }

    fn poll_in(&self) -> bool {
        false
    }

    /// `tun_sock_writeable`: only while the device is up.
    fn poll_out(&self) -> bool {
        self.attached().is_some_and(|d| d.running())
    }

    fn poll_writable(&self) -> bool {
        self.poll_out()
    }

    fn poll_err(&self) -> bool {
        self.attached().is_none()
    }

    fn poll_hup(&self) -> bool {
        false
    }

    fn wait_queue(&self) -> u32 {
        self.queue.id()
    }

    fn wakes(&self) -> Option<u64> {
        Some(self.queue.wakes())
    }

    fn seek(&self, _offset: i64, _whence: u32) -> Option<SysResult> {
        Some(Err(Errno::ESPIPE))
    }

    fn as_tun(self: Arc<Self>) -> Option<Arc<TunFile>> {
        Some(self)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(match &self.node {
            Some(node) => node(),
            None => Metadata {
                file_type: FileType::CharDevice,
                size: 0,
                mode: 0o600,
                ino: crate::vfs::anon_ino(self as *const Self as *const u8),
                mtime: 0,
                nlink: 1,
                rdev: crate::vfs::devices::makedev(10, MISC_MINOR),
                dev: 0,
                times: Default::default(),
                owner: None,
            },
        })
    }
}
