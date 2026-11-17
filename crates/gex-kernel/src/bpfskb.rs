//! A packet as a BPF program sees it: `struct __sk_buff`, each field as
//! the verifier lets a program of its type read or write it
//! (`sk_filter_is_valid_access`, `tc_cls_act_is_valid_access`,
//! `cg_skb_is_valid_access` in `net/core/filter.c`), and the packet's bytes
//! from its data. `BPF_PROG_TEST_RUN` makes one as `bpf_prog_test_run_skb`
//! does; the socket hooks will make one for each packet.

use crate::bpfprog::prog_type;
use crate::bpfrun::{Context, Field};

/// `struct __sk_buff`'s fields: offset, and size (8 for the 64-bit ones).
pub mod off {
    pub const LEN: u32 = 0;
    pub const PKT_TYPE: u32 = 4;
    pub const MARK: u32 = 8;
    pub const QUEUE_MAPPING: u32 = 12;
    pub const PROTOCOL: u32 = 16;
    pub const VLAN_PRESENT: u32 = 20;
    pub const VLAN_TCI: u32 = 24;
    pub const VLAN_PROTO: u32 = 28;
    pub const PRIORITY: u32 = 32;
    pub const INGRESS_IFINDEX: u32 = 36;
    pub const IFINDEX: u32 = 40;
    pub const TC_INDEX: u32 = 44;
    pub const CB: u32 = 48;
    pub const HASH: u32 = 68;
    pub const TC_CLASSID: u32 = 72;
    pub const DATA: u32 = 76;
    pub const DATA_END: u32 = 80;
    pub const NAPI_ID: u32 = 84;
    pub const FAMILY: u32 = 88;
    pub const REMOTE_IP4: u32 = 92;
    pub const LOCAL_IP4: u32 = 96;
    pub const REMOTE_IP6: u32 = 100;
    pub const LOCAL_IP6: u32 = 116;
    pub const REMOTE_PORT: u32 = 132;
    pub const LOCAL_PORT: u32 = 136;
    pub const DATA_META: u32 = 140;
    pub const FLOW_KEYS: u32 = 144;
    pub const TSTAMP: u32 = 152;
    pub const WIRE_LEN: u32 = 160;
    pub const GSO_SEGS: u32 = 164;
    pub const SK: u32 = 168;
    pub const GSO_SIZE: u32 = 176;
    pub const TSTAMP_TYPE: u32 = 180;
    pub const HWTSTAMP: u32 = 184;
    /// `sizeof(struct __sk_buff)`.
    pub const SIZE: u32 = 192;
}

/// A packet and what is said of it.
#[derive(Debug, Clone, Default)]
pub struct Skb {
    /// The program's type: what it may see.
    pub ty: u32,
    /// From the packet's data (the network header, or the link layer's
    /// for a classifier) to its end.
    pub data: Vec<u8>,
    pub pkt_type: u32,
    pub mark: u32,
    pub queue_mapping: u32,
    /// As it is in memory: network order.
    pub protocol: u16,
    pub priority: u32,
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    pub tc_index: u32,
    pub cb: [u32; 5],
    pub hash: u32,
    pub tc_classid: u32,
    pub tstamp: u64,
    pub wire_len: u32,
    pub gso_segs: u32,
    pub gso_size: u32,
    pub hwtstamp: u64,
    /// The socket's: family, and its addresses and ports as the fields
    /// give them (network order but for the local port).
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub socket_uid: u64,
    pub socket_cookie: u64,
    /// The calling task's real group and user.
    pub uid_gid: u64,
}

impl Skb {
    /// Whether a program of this type may read the field at `off`.
    fn readable(&self, off: u32) -> bool {
        use off::*;
        let direct = matches!(self.ty, prog_type::SCHED_CLS | prog_type::SCHED_ACT | prog_type::CGROUP_SKB);
        match off {
            TC_CLASSID => matches!(self.ty, prog_type::SCHED_CLS | prog_type::SCHED_ACT),
            DATA | DATA_END => direct,
            DATA_META => matches!(self.ty, prog_type::SCHED_CLS | prog_type::SCHED_ACT),
            FAMILY..DATA_META => self.ty == prog_type::CGROUP_SKB,
            FLOW_KEYS => false,
            TSTAMP | WIRE_LEN | HWTSTAMP => self.ty != prog_type::SOCKET_FILTER,
            _ => off < SIZE,
        }
    }

    /// Whether it may write it.
    fn writable(&self, off: u32) -> bool {
        use off::*;
        let cb = (CB..CB + 20).contains(&off);
        match self.ty {
            prog_type::SOCKET_FILTER => cb,
            prog_type::CGROUP_SKB => cb || matches!(off, MARK | PRIORITY | TSTAMP),
            prog_type::SCHED_CLS | prog_type::SCHED_ACT => cb || matches!(off, MARK | PRIORITY | TC_INDEX | TC_CLASSID | QUEUE_MAPPING | TSTAMP),
            _ => false,
        }
    }

    /// The 32-bit field holding `off`, and its value (or the 64-bit one).
    fn value(&self, off: u32) -> Option<(u32, u8, Field)> {
        use off::*;
        let s = |v: u32| Some(Field::Scalar(v as u64));
        let (base, size, v) = match off {
            HWTSTAMP..=191 => (HWTSTAMP, 8, Some(Field::Scalar(self.hwtstamp))),
            TSTAMP..=159 => (TSTAMP, 8, Some(Field::Scalar(self.tstamp))),
            REMOTE_IP6..=115 => {
                let k = (off - REMOTE_IP6) / 4;
                (REMOTE_IP6 + 4 * k, 4, s(self.remote_ip6[k as usize]))
            }
            LOCAL_IP6..=131 => {
                let k = (off - LOCAL_IP6) / 4;
                (LOCAL_IP6 + 4 * k, 4, s(self.local_ip6[k as usize]))
            }
            CB..=67 => {
                let k = (off - CB) / 4;
                (CB + 4 * k, 4, s(self.cb[k as usize]))
            }
            _ => {
                let base = off & !3;
                let v = match base {
                    LEN => s(self.data.len() as u32),
                    PKT_TYPE => s(self.pkt_type),
                    MARK => s(self.mark),
                    QUEUE_MAPPING => s(self.queue_mapping),
                    PROTOCOL => s(self.protocol.swap_bytes() as u32),
                    VLAN_PRESENT | VLAN_TCI | VLAN_PROTO | TC_INDEX | NAPI_ID => s(if base == TC_INDEX { self.tc_index } else { 0 }),
                    PRIORITY => s(self.priority),
                    INGRESS_IFINDEX => s(self.ingress_ifindex),
                    IFINDEX => s(self.ifindex),
                    HASH => s(self.hash),
                    TC_CLASSID => s(self.tc_classid),
                    DATA => Some(Field::Packet(0)),
                    DATA_END => Some(Field::Packet(self.data.len() as u64)),
                    FAMILY => s(self.family),
                    REMOTE_IP4 => s(self.remote_ip4),
                    LOCAL_IP4 => s(self.local_ip4),
                    REMOTE_PORT => s(self.remote_port),
                    LOCAL_PORT => s(self.local_port),
                    DATA_META => Some(Field::Packet(0)),
                    WIRE_LEN => s(self.wire_len),
                    GSO_SEGS => s(self.gso_segs),
                    GSO_SIZE => s(self.gso_size),
                    TSTAMP_TYPE => s(0),
                    _ => None,
                };
                (base, 4, v)
            }
        };
        Some((base, size, v?))
    }
}

impl Context for Skb {
    fn load(&mut self, off: u32, size: u8) -> Option<Field> {
        if !self.readable(off) {
            return None;
        }
        let (base, fsize, v) = self.value(off)?;
        match v {
            // A pointer is had whole.
            Field::Packet(_) | Field::Sock | Field::Buf(_) => (off == base && size == 4).then_some(v),
            Field::Scalar(x) => {
                // The field whole, or a narrower part of it.
                let within = off - base;
                if size > fsize || !matches!(size, 1 | 2 | 4 | 8) || within % size as u32 != 0 || within + size as u32 > fsize as u32 {
                    return None;
                }
                let bytes = x.to_le_bytes();
                let mut w = [0u8; 8];
                w[..size as usize].copy_from_slice(&bytes[within as usize..within as usize + size as usize]);
                Some(Field::Scalar(u64::from_le_bytes(w)))
            }
        }
    }

    fn store(&mut self, off: u32, size: u8, value: u64) -> Option<()> {
        if !self.writable(off) {
            return None;
        }
        let (base, fsize, _) = self.value(off)?;
        if off != base || size != fsize {
            return None;
        }
        let v = value as u32;
        use off::*;
        match base {
            MARK => self.mark = v,
            PRIORITY => self.priority = v,
            TC_INDEX => self.tc_index = v,
            TC_CLASSID => self.tc_classid = v,
            QUEUE_MAPPING => self.queue_mapping = v,
            TSTAMP => self.tstamp = value,
            b if (CB..CB + 20).contains(&b) => self.cb[((b - CB) / 4) as usize] = v,
            _ => return None,
        }
        Some(())
    }

    fn packet(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.data)
    }

    fn packet_writable(&self) -> bool {
        matches!(self.ty, prog_type::SCHED_CLS | prog_type::SCHED_ACT)
    }

    fn socket_uid(&mut self) -> u64 {
        self.socket_uid
    }

    fn socket_cookie(&mut self) -> u64 {
        self.socket_cookie
    }

    fn current_uid_gid(&mut self) -> u64 {
        self.uid_gid
    }
}

/// `struct ethhdr`'s length.
const ETH_HLEN: usize = 14;

/// What `bpf_prog_test_run_skb` makes of a test's packet and context:
/// the packet as the loopback device (or the interface the context names)
/// would have taken it in (`eth_type_trans`), its link layer's header
/// pulled off for a program that does not see it, the context's fields put
/// on it (`convert___skb_to_skb`). `Err` as that refuses.
pub fn for_test(ty: u32, packet: &[u8], ctx: Option<&[u8]>) -> Result<Skb, crate::errno::Errno> {
    use crate::errno::Errno;
    if packet.len() < ETH_HLEN {
        return Err(Errno::EINVAL);
    }
    let u32_at = |c: &[u8], at: u32| u32::from_le_bytes(c[at as usize..at as usize + 4].try_into().unwrap());
    let u64_at = |c: &[u8], at: u32| u64::from_le_bytes(c[at as usize..at as usize + 8].try_into().unwrap());
    let mut skb = Skb { ty, ifindex: 1, ..Default::default() };
    if let Some(c) = ctx {
        let ifindex = u32_at(c, off::IFINDEX);
        if ifindex > 1 {
            if !crate::netlink::iface_exists(ifindex) {
                return Err(Errno::ENODEV);
            }
            skb.ifindex = ifindex;
        }
    }
    // `eth_type_trans` on a device whose address is all zeros (the
    // loopback's; eth0's here is not, but a test names it rarely).
    let dest = &packet[0..6];
    let own = if skb.ifindex == 2 { [0x02, 0, 0, 0, 0, 1] } else { [0u8; 6] };
    skb.pkt_type = if dest == own {
        0
    } else if dest[0] & 1 != 0 {
        if dest == [0xff; 6] { 1 } else { 2 }
    } else {
        3
    };
    let proto = u16::from_be_bytes([packet[12], packet[13]]);
    skb.protocol = if proto >= 0x600 {
        proto
    } else if packet.len() >= ETH_HLEN + 2 && packet[14] == 0xff && packet[15] == 0xff {
        0x0001
    } else {
        0x0004
    };
    let net = &packet[ETH_HLEN..];
    match skb.protocol {
        0x0800 => {
            if net.len() < 20 {
                return Err(Errno::EINVAL);
            }
            skb.family = 2;
            skb.local_ip4 = u32::from_le_bytes(net[12..16].try_into().unwrap());
            skb.remote_ip4 = u32::from_le_bytes(net[16..20].try_into().unwrap());
        }
        0x86dd => {
            if net.len() < 40 {
                return Err(Errno::EINVAL);
            }
            skb.family = 10;
            for k in 0..4 {
                skb.local_ip6[k] = u32::from_le_bytes(net[8 + 4 * k..12 + 4 * k].try_into().unwrap());
                skb.remote_ip6[k] = u32::from_le_bytes(net[24 + 4 * k..28 + 4 * k].try_into().unwrap());
            }
        }
        _ => {}
    }
    // A classifier sees the link layer's header; the others start at the
    // network header.
    let l2 = matches!(ty, prog_type::SCHED_CLS | prog_type::SCHED_ACT);
    skb.data = if l2 { packet.to_vec() } else { net.to_vec() };
    skb.wire_len = skb.data.len() as u32;
    if let Some(c) = ctx {
        // Only these may be given (`convert___skb_to_skb`).
        use off::*;
        let zero = |from: u32, to: u32| c[from as usize..to as usize].iter().all(|b| *b == 0);
        if !zero(0, MARK) || !zero(MARK + 4, PRIORITY) || !zero(IFINDEX + 4, CB) || !zero(CB + 20, TSTAMP) || !zero(GSO_SEGS + 4, GSO_SIZE) || !zero(GSO_SIZE + 4, HWTSTAMP) || !zero(HWTSTAMP + 8, SIZE) {
            return Err(Errno::EINVAL);
        }
        skb.mark = u32_at(c, MARK);
        skb.priority = u32_at(c, PRIORITY);
        skb.ingress_ifindex = u32_at(c, INGRESS_IFINDEX);
        skb.tstamp = u64_at(c, TSTAMP);
        for k in 0..5 {
            skb.cb[k] = u32_at(c, CB + 4 * k as u32);
        }
        let wire = u32_at(c, WIRE_LEN);
        if wire != 0 {
            // `GSO_LEGACY_MAX_SIZE`.
            if wire < skb.data.len() as u32 || wire > 65536 {
                return Err(Errno::EINVAL);
            }
            skb.wire_len = wire;
        }
        // `GSO_MAX_SEGS`.
        if u32_at(c, GSO_SEGS) > 65535 {
            return Err(Errno::EINVAL);
        }
        skb.gso_segs = u32_at(c, GSO_SEGS);
        skb.gso_size = u32_at(c, GSO_SIZE);
        skb.hwtstamp = u64_at(c, HWTSTAMP);
    }
    Ok(skb)
}

impl Skb {
    /// After a test's run: the packet as it is given back (with the link
    /// layer's header, zeroed, for a program that did not see it), and the
    /// context (`convert_skb_to___skb`) over what was given.
    pub fn after_test(&self, ctx: &mut [u8]) -> Vec<u8> {
        use off::*;
        let l2 = matches!(self.ty, prog_type::SCHED_CLS | prog_type::SCHED_ACT);
        let mut out = if l2 { Vec::new() } else { vec![0u8; ETH_HLEN] };
        out.extend_from_slice(&self.data);
        let mut put = |at: u32, v: &[u8]| ctx[at as usize..at as usize + v.len()].copy_from_slice(v);
        put(MARK, &self.mark.to_le_bytes());
        put(PRIORITY, &self.priority.to_le_bytes());
        put(INGRESS_IFINDEX, &self.ingress_ifindex.to_le_bytes());
        put(IFINDEX, &self.ifindex.to_le_bytes());
        put(TSTAMP, &self.tstamp.to_le_bytes());
        for k in 0..5 {
            put(CB + 4 * k as u32, &self.cb[k].to_le_bytes());
        }
        put(WIRE_LEN, &self.wire_len.to_le_bytes());
        put(GSO_SEGS, &self.gso_segs.to_le_bytes());
        put(HWTSTAMP, &self.hwtstamp.to_le_bytes());
        out
    }
}
