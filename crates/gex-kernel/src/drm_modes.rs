//! The display modes a virtio-gpu connector offers, as Linux 6.18 makes
//! them when its master probes it (`drm_helper_probe_single_connector_modes`
//! with `virtio_gpu_conn_get_modes`): the preferred mode the CVT formula
//! gives for the size the host reports (`drm_cvt_mode`, `drm_modes.c`), and
//! every DMT mode (`drm_dmt_modes`, `drm_edid.c`) of up to 8192 by 8192 and
//! 61 Hz that is not interlaced, sorted as `drm_mode_compare` sorts.
//!
//! A mode leaves the kernel as `struct drm_mode_modeinfo` (68 bytes).

/// `DRM_MODE_TYPE_PREFERRED`, `DRM_MODE_TYPE_DRIVER`.
pub const TYPE_PREFERRED: u32 = 1 << 3;
pub const TYPE_DRIVER: u32 = 1 << 6;
/// `DRM_MODE_TYPE_ALL`: the type bits `drm_mode_convert_umode` keeps.
pub const TYPE_ALL: u32 = TYPE_PREFERRED | TYPE_DRIVER | 1 << 5 /* USERDEF */;

/// A mode's timings and name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mode {
    pub clock: u32,
    pub h: [u16; 5],
    pub v: [u16; 5],
    pub flags: u32,
    pub kind: u32,
    pub name: String,
}

/// The DMT modes a probe keeps, in table order: name, clock, hdisplay,
/// hsync start and end, htotal, vdisplay, vsync start and end, vtotal,
/// flags (`PHSYNC` 1, `NHSYNC` 2, `PVSYNC` 4, `NVSYNC` 8).
const DMT: [(&str, u32, [u16; 4], [u16; 4], u32); 34] = [
    ("640x480", 25175, [640, 656, 752, 800], [480, 490, 492, 525], 0xa),
    ("800x600", 36000, [800, 824, 896, 1024], [600, 601, 603, 625], 0x5),
    ("800x600", 40000, [800, 840, 968, 1056], [600, 601, 605, 628], 0x5),
    ("848x480", 33750, [848, 864, 976, 1088], [480, 486, 494, 517], 0xa),
    ("1024x768", 65000, [1024, 1048, 1184, 1344], [768, 771, 777, 806], 0xa),
    ("1280x768", 68250, [1280, 1328, 1360, 1440], [768, 771, 778, 790], 0x9),
    ("1280x768", 79500, [1280, 1344, 1472, 1664], [768, 771, 778, 798], 0x6),
    ("1280x800", 71000, [1280, 1328, 1360, 1440], [800, 803, 809, 823], 0x9),
    ("1280x800", 83500, [1280, 1352, 1480, 1680], [800, 803, 809, 831], 0x6),
    ("1280x960", 108000, [1280, 1376, 1488, 1800], [960, 961, 964, 1000], 0x5),
    ("1280x1024", 108000, [1280, 1328, 1440, 1688], [1024, 1025, 1028, 1066], 0x5),
    ("1360x768", 85500, [1360, 1424, 1536, 1792], [768, 771, 777, 795], 0x5),
    ("1400x1050", 101000, [1400, 1448, 1480, 1560], [1050, 1053, 1057, 1080], 0x9),
    ("1400x1050", 121750, [1400, 1488, 1632, 1864], [1050, 1053, 1057, 1089], 0x6),
    ("1440x900", 88750, [1440, 1488, 1520, 1600], [900, 903, 909, 926], 0x9),
    ("1440x900", 106500, [1440, 1520, 1672, 1904], [900, 903, 909, 934], 0x6),
    ("1600x1200", 162000, [1600, 1664, 1856, 2160], [1200, 1201, 1204, 1250], 0x5),
    ("1680x1050", 119000, [1680, 1728, 1760, 1840], [1050, 1053, 1059, 1080], 0x9),
    ("1680x1050", 146250, [1680, 1784, 1960, 2240], [1050, 1053, 1059, 1089], 0x6),
    ("1792x1344", 204750, [1792, 1920, 2120, 2448], [1344, 1345, 1348, 1394], 0x6),
    ("1856x1392", 218250, [1856, 1952, 2176, 2528], [1392, 1393, 1396, 1439], 0x6),
    ("1920x1200", 154000, [1920, 1968, 2000, 2080], [1200, 1203, 1209, 1235], 0x9),
    ("1920x1200", 193250, [1920, 2056, 2256, 2592], [1200, 1203, 1209, 1245], 0x6),
    ("1920x1440", 234000, [1920, 2048, 2256, 2600], [1440, 1441, 1444, 1500], 0x6),
    ("2560x1600", 268500, [2560, 2608, 2640, 2720], [1600, 1603, 1609, 1646], 0x9),
    ("2560x1600", 348500, [2560, 2752, 3032, 3504], [1600, 1603, 1609, 1658], 0x6),
    ("1366x768", 85500, [1366, 1436, 1579, 1792], [768, 771, 774, 798], 0x5),
    ("1920x1080", 148500, [1920, 2008, 2052, 2200], [1080, 1084, 1089, 1125], 0xa),
    ("1600x900", 108000, [1600, 1624, 1704, 1800], [900, 901, 904, 1000], 0x5),
    ("2048x1152", 162000, [2048, 2074, 2154, 2250], [1152, 1153, 1156, 1200], 0x5),
    ("1280x720", 74250, [1280, 1390, 1430, 1650], [720, 725, 730, 750], 0x5),
    ("1366x768", 72000, [1366, 1380, 1436, 1500], [768, 769, 772, 800], 0x5),
    ("4096x2160", 556744, [4096, 4104, 4136, 4176], [2160, 2208, 2216, 2222], 0x9),
    ("4096x2160", 556188, [4096, 4104, 4136, 4176], [2160, 2208, 2216, 2222], 0x9),
];

impl Mode {
    fn of(name: &str, clock: u32, h: [u16; 4], v: [u16; 4], flags: u32, kind: u32) -> Mode {
        Mode { clock, h: [h[0], h[1], h[2], h[3], 0], v: [v[0], v[1], v[2], v[3], 0], flags, kind, name: name.to_string() }
    }

    /// `drm_mode_vrefresh`, for a mode neither interlaced nor scanned twice.
    pub fn vrefresh(&self) -> u32 {
        let (ht, vt) = (self.h[3] as u64, self.v[3] as u64);
        if ht == 0 || vt == 0 {
            return 0;
        }
        let num = self.clock as u64 * 1000;
        let den = ht * vt;
        ((num + den / 2) / den) as u32
    }

    /// `struct drm_mode_modeinfo` (`drm_mode_convert_to_umode`).
    pub fn to_umode(&self) -> [u8; 68] {
        let mut b = [0u8; 68];
        b[0..4].copy_from_slice(&self.clock.to_le_bytes());
        for (i, x) in self.h.iter().chain(self.v.iter()).enumerate() {
            b[4 + i * 2..6 + i * 2].copy_from_slice(&x.to_le_bytes());
        }
        b[24..28].copy_from_slice(&self.vrefresh().to_le_bytes());
        b[28..32].copy_from_slice(&self.flags.to_le_bytes());
        b[32..36].copy_from_slice(&self.kind.to_le_bytes());
        let n = self.name.as_bytes();
        let n = &n[..n.len().min(31)];
        b[36..36 + n.len()].copy_from_slice(n);
        b
    }
}

/// `drm_cvt_mode(dev, w, h, 60, false, false, false)`, preferred, as
/// virtio-gpu adds it for the host's size. Its clock is not rounded to
/// 250 kHz: the kernel takes the remainder while the clock is still 0.
pub fn cvt(w: u32, h: u32) -> Mode {
    let (w, h) = (w as i64, h as i64);
    let hd = w - w % 8;
    let vd = h;
    let vsync = if h % 3 == 0 && h * 4 / 3 == w {
        4
    } else if h % 9 == 0 && h * 16 / 9 == w {
        5
    } else if h % 10 == 0 && h * 16 / 10 == w {
        6
    } else if (h % 4 == 0 && h * 5 / 4 == w) || (h % 9 == 0 && h * 15 / 9 == w) {
        7
    } else {
        10
    };
    let hperiod = (1000 * 1_000_000 - 550 * 1000 * 60) * 2 / (((vd + 3) * 2) * 60);
    let t = 550 * 1000 / hperiod + 1;
    let vsbp = t.max(vsync + 3);
    let vtotal = vd + vsbp + 3;
    let mut hbp = 30 * 1000 - 300 * hperiod / 1000;
    if hbp < 20000 {
        hbp = 20000;
    }
    let mut hblank = hd * hbp / (100_000 - hbp);
    hblank -= hblank % 16;
    let htotal = hd + hblank;
    let hsync_end = hd + hblank / 2;
    let mut hsync_start = hsync_end - htotal * 8 / 100;
    hsync_start += 8 - hsync_start % 8;
    let vsync_start = vd + 3;
    let vsync_end = vsync_start + vsync;
    let clock = htotal * 1000 * 1000 / hperiod;
    Mode {
        clock: clock as u32,
        h: [hd as u16, hsync_start as u16, hsync_end as u16, htotal as u16, 0],
        v: [vd as u16, vsync_start as u16, vsync_end as u16, vtotal as u16, 0],
        flags: 0x6,
        kind: TYPE_PREFERRED,
        name: format!("{hd}x{vd}"),
    }
}

/// The modes a probe leaves for a host that reports `w` by `h`, in the
/// order GETCONNECTOR gives them.
pub fn probe(w: u32, h: u32) -> Vec<Mode> {
    let zero = w == 0 || h == 0;
    let mut modes: Vec<Mode> = DMT
        .iter()
        .map(|&(n, c, hh, vv, f)| {
            let pref = zero && hh[0] == 1024 && vv[0] == 768;
            Mode::of(n, c, hh, vv, f, TYPE_DRIVER | if pref { TYPE_PREFERRED } else { 0 })
        })
        .collect();
    if !zero {
        let m = cvt(w, h);
        // `virtio_gpu_conn_mode_valid`: a preferred mode within 16 of
        // the host's size; and nothing past 8192 survives the probe.
        let ok = (m.h[0] == 1024 && m.v[0] == 768) || (w.saturating_sub(16) <= m.h[0] as u32 && m.h[0] as u32 <= w && h.saturating_sub(16) <= m.v[0] as u32 && m.v[0] as u32 <= h);
        if ok && w <= 8192 && h <= 8192 {
            modes.push(m);
        }
    }
    // `drm_mode_compare`: preferred first, then the larger area, the
    // higher refresh, the higher clock (a stable sort).
    modes.sort_by(|a, b| {
        let key = |m: &Mode| (m.kind & TYPE_PREFERRED == 0, std::cmp::Reverse(m.h[0] as u32 * m.v[0] as u32), std::cmp::Reverse(m.vrefresh()), std::cmp::Reverse(m.clock));
        key(a).cmp(&key(b))
    });
    modes
}

/// Whether two modes are the same timings (`drm_mode_equal`: clock,
/// timings, flags; not the name or type).
pub fn same_timings(a: &[u8; 68], b: &[u8; 68]) -> bool {
    a[0..24] == b[0..24] && a[28..32] == b[28..32]
}

/// `drm_mode_convert_umode` and `drm_mode_validate_basic`: whether user
/// mode bytes make a mode an atomic `MODE_ID` may name.
pub fn umode_valid(b: &[u8; 68]) -> bool {
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u16_at = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
    let (clock, vrefresh, flags) = (u32_at(0), u32_at(24), u32_at(28));
    if clock > i32::MAX as u32 || vrefresh > i32::MAX as u32 {
        return false;
    }
    // Aspect-ratio bits: none, 4:3, 16:9, 64:27, 256:135.
    if !matches!((flags >> 19) & 0xf, 0..=4) {
        return false;
    }
    // `DRM_MODE_FLAG_ALL`: bits 0-9, 12, 13 and the 3D field (14-18),
    // whose value may be at most SIDE_BY_SIDE_HALF (8).
    let all = 0x3ff | 1 << 12 | 1 << 13 | 0x1f << 14;
    if flags & !(all | 0xf << 19) != 0 || (flags >> 14) & 0x1f > 8 {
        return false;
    }
    let (hd, hss, hse, ht) = (u16_at(4), u16_at(6), u16_at(8), u16_at(10));
    let (vd, vss, vse, vt) = (u16_at(14), u16_at(16), u16_at(18), u16_at(20));
    clock != 0 && hd != 0 && hss >= hd && hse >= hss && ht >= hse && vd != 0 && vss >= vd && vse >= vss && vt >= vse
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cvt_mode_is_the_kernels() {
        let m = cvt(1024, 768);
        assert_eq!((m.clock, m.h, m.v), (63531, [1024, 1072, 1176, 1328, 0], [768, 771, 775, 798, 0]));
        let m = cvt(1080, 1920);
        assert_eq!((m.clock, m.h, m.v), (176589, [1080, 1168, 1280, 1480, 0], [1920, 1923, 1933, 1989, 0]));
        let m = cvt(1280, 720);
        assert_eq!((m.clock, m.h, m.v), (74648, [1280, 1344, 1472, 1664, 0], [720, 723, 728, 748, 0]));
    }

    #[test]
    fn a_probe_lists_what_linux_lists() {
        let none = probe(0, 0);
        assert_eq!(none.len(), 34);
        assert_eq!((none[0].name.as_str(), none[0].clock, none[0].kind), ("1024x768", 65000, 0x48));
        let names: Vec<(&str, u32)> = none.iter().map(|m| (m.name.as_str(), m.clock)).collect();
        assert_eq!(&names[1..5], &[("4096x2160", 556744), ("4096x2160", 556188), ("2560x1600", 348500), ("2560x1600", 268500)]);
        assert_eq!(&names[30..], &[("800x600", 40000), ("800x600", 36000), ("848x480", 33750), ("640x480", 25175)]);
        let with = probe(1080, 1920);
        assert_eq!(with.len(), 35);
        assert_eq!((with[0].name.as_str(), with[0].kind), ("1080x1920", 8));
        let at = with.iter().position(|m| m.name == "1024x768").unwrap();
        assert_eq!((with[at - 1].name.as_str(), with[at + 1].name.as_str(), with[at].kind), ("1280x720", "800x600", 0x40));
        assert_eq!(none[31].vrefresh(), 56);
    }
}
