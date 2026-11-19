//! A `virtio_gpu` DRM device, as Linux 6.18's driver (`drivers/gpu/drm/virtio`
//! and the DRM core at android17-6.18) presents a virtio-gpu with no 3D
//! and one scanout: `/dev/dri/card0` (226:0) for mode setting and
//! `/dev/dri/renderD128` (226:128) for buffers.
//!
//! What uses it is the emulator image's own guest-rendering stack: minigbm
//! (dumb buffers through the render node, shared as dma-bufs) and the
//! goldfish composer's `GuestFrameComposer` (atomic KMS on card0, with a
//! CRTC out-fence each frame), drawing with SwiftShader. On the emulator a
//! host renders what is scanned out; here the scanned-out buffer is the
//! kernel's to read ([`Gpu::scanout`]), and `GEX_VIRTIO_GPU_FRAME=<file>`
//! writes it as a PPM image (at most once a second).
//!
//! Off unless asked: `GEX_VIRTIO_GPU=<width>x<height>` gives the host's
//! display size, natively. The page's processes are each a kernel, and a
//! buffer here is the one kernel's.
//!
//! **Memory.** A buffer object is the kernel's bytes, and a mapping of one
//! (through the DRM descriptor at its offset, or through its dma-buf) is a
//! shared file mapping, kept in step as every shared mapping here is
//! (`crate::syscalls::SharedMap`): written back at `msync`, `munmap`, a
//! futex wake, and before this driver's atomic commit and a dma-buf `SYNC`
//! (both in the syscall layer); taken in by other processes at their next
//! system call. Linux maps the same pages into every process.
//!
//! The ids, values, errors and orders here are the spec written from the
//! 6.18 source (each fact with its file and line in that tree), checked
//! by `tests/android/src/drm.c` against Linux 7.0's driver.
//!
//! Not here, and said when asked: syncobjs, leases, legacy mode setting
//! (SETCRTC, SETPLANE, CURSOR, PAGE_FLIP, DIRTYFB, SETPROPERTY), GETFB and
//! GETFB2, flink names, RESOURCE_CREATE, the hotplug events a host's
//! display change sends, and the connector's sysfs directory.

use crate::drm_modes;
use crate::errno::Errno;
use crate::file::{FdTable, OpenFile};
use crate::syncfile::{Fence, SyncFile};
use crate::vfs::devices::NodeMeta;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use crate::errno::SysResult;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// `DRM_MAJOR`.
pub const MAJOR: u32 = 226;

// Mode objects, as `virtio_gpu_modeset_init` makes them after the 32
// standard properties: the primary plane, the cursor plane (whose init
// makes HOTSPOT_X and HOTSPOT_Y), the CRTC, the connector, the encoder.
const PRIMARY: u32 = 33;
const CURSOR: u32 = 34;
const CRTC: u32 = 37;
const CONN: u32 = 38;
const ENC: u32 = 39;
/// The first id an object made after load gets.
const FIRST_FREE: u32 = 40;

// `DRM_MODE_OBJECT_*`.
const OBJ_CRTC: u32 = 0xcccc_cccc;
const OBJ_CONNECTOR: u32 = 0xc0c0_c0c0;
const OBJ_ENCODER: u32 = 0xe0e0_e0e0;
const OBJ_PROPERTY: u32 = 0xb0b0_b0b0;
const OBJ_FB: u32 = 0xfbfb_fbfb;
const OBJ_BLOB: u32 = 0xbbbb_bbbb;
const OBJ_PLANE: u32 = 0xeeee_eeee;

// `DRM_MODE_PROP_*`.
const RANGE: u32 = 0x2;
const IMMUTABLE: u32 = 0x4;
const ENUM: u32 = 0x8;
const BLOB: u32 = 0x10;
const OBJECT: u32 = 0x40;
const SIGNED: u32 = 0x80;
const ATOMIC: u32 = 0x8000_0000;

/// A property: its name, flags, values (a range's bounds, an object's type)
/// and enum names.
struct Prop {
    name: &'static str,
    flags: u32,
    values: &'static [u64],
    enums: &'static [(u64, &'static str)],
}

const fn p(name: &'static str, flags: u32, values: &'static [u64]) -> Prop {
    Prop { name, flags, values, enums: &[] }
}

const NEG: u64 = 0xffff_ffff_8000_0000;
const DPMS: [(u64, &str); 4] = [(0, "On"), (1, "Standby"), (2, "Suspend"), (3, "Off")];
const LINK: [(u64, &str); 2] = [(0, "Good"), (1, "Bad")];
const PLANE_TYPE: [(u64, &str); 3] = [(0, "Overlay"), (1, "Primary"), (2, "Cursor")];

/// The properties by id (`drm_mode_create_standard_properties`, then the
/// cursor plane's hotspot pair).
static PROPS: [Prop; 36] = [
    p("EDID", BLOB | IMMUTABLE, &[]),
    Prop { name: "DPMS", flags: ENUM, values: &[0, 1, 2, 3], enums: &DPMS },
    p("PATH", BLOB | IMMUTABLE, &[]),
    p("TILE", BLOB | IMMUTABLE, &[]),
    Prop { name: "link-status", flags: ENUM, values: &[0, 1], enums: &LINK },
    p("non-desktop", RANGE | IMMUTABLE, &[0, 1]),
    p("HDR_OUTPUT_METADATA", BLOB, &[]),
    Prop { name: "type", flags: ENUM | IMMUTABLE, values: &[0, 1, 2], enums: &PLANE_TYPE },
    p("SRC_X", RANGE | ATOMIC, &[0, 0xffff_ffff]),
    p("SRC_Y", RANGE | ATOMIC, &[0, 0xffff_ffff]),
    p("SRC_W", RANGE | ATOMIC, &[0, 0xffff_ffff]),
    p("SRC_H", RANGE | ATOMIC, &[0, 0xffff_ffff]),
    p("CRTC_X", SIGNED | ATOMIC, &[NEG, 0x7fff_ffff]),
    p("CRTC_Y", SIGNED | ATOMIC, &[NEG, 0x7fff_ffff]),
    p("CRTC_W", RANGE | ATOMIC, &[0, 0x7fff_ffff]),
    p("CRTC_H", RANGE | ATOMIC, &[0, 0x7fff_ffff]),
    p("FB_ID", OBJECT | ATOMIC, &[OBJ_FB as u64]),
    p("IN_FENCE_FD", SIGNED | ATOMIC, &[u64::MAX, 0x7fff_ffff]),
    p("OUT_FENCE_PTR", RANGE | ATOMIC, &[0, u64::MAX]),
    p("CRTC_ID", OBJECT | ATOMIC, &[OBJ_CRTC as u64]),
    p("FB_DAMAGE_CLIPS", BLOB | ATOMIC, &[]),
    p("ACTIVE", RANGE | ATOMIC, &[0, 1]),
    p("MODE_ID", BLOB | ATOMIC, &[]),
    p("VRR_ENABLED", RANGE, &[0, 1]),
    p("DEGAMMA_LUT", BLOB, &[]),
    p("DEGAMMA_LUT_SIZE", RANGE | IMMUTABLE, &[0, 0xffff_ffff]),
    p("CTM", BLOB, &[]),
    p("GAMMA_LUT", BLOB, &[]),
    p("GAMMA_LUT_SIZE", RANGE | IMMUTABLE, &[0, 0xffff_ffff]),
    p("IN_FORMATS", BLOB | IMMUTABLE, &[]),
    p("IN_FORMATS_ASYNC", BLOB | IMMUTABLE, &[]),
    p("SIZE_HINTS", BLOB | IMMUTABLE, &[]),
    // 33 and 34 are the planes.
    p("", 0, &[]),
    p("", 0, &[]),
    p("HOTSPOT_X", SIGNED, &[NEG, 0x7fff_ffff]),
    p("HOTSPOT_Y", SIGNED, &[NEG, 0x7fff_ffff]),
];

fn prop(id: u32) -> Option<&'static Prop> {
    PROPS.get((id as usize).checked_sub(1)?).filter(|p| !p.name.is_empty())
}

// Property ids.
const P_DPMS: u32 = 2;
const P_TILE: u32 = 4;
const P_LINK: u32 = 5;
const P_NONDESKTOP: u32 = 6;
const P_TYPE: u32 = 8;
const P_SRC_X: u32 = 9;
const P_SRC_Y: u32 = 10;
const P_SRC_W: u32 = 11;
const P_SRC_H: u32 = 12;
const P_CRTC_X: u32 = 13;
const P_CRTC_Y: u32 = 14;
const P_CRTC_W: u32 = 15;
const P_CRTC_H: u32 = 16;
const P_FB_ID: u32 = 17;
const P_IN_FENCE: u32 = 18;
const P_OUT_FENCE: u32 = 19;
const P_CRTC_ID: u32 = 20;
const P_DAMAGE: u32 = 21;
const P_ACTIVE: u32 = 22;
const P_MODE_ID: u32 = 23;
const P_VRR: u32 = 24;
const P_HOT_X: u32 = 35;
const P_HOT_Y: u32 = 36;

/// What an object has attached, in attach order.
fn attached(obj: u32) -> &'static [u32] {
    match obj {
        PRIMARY => &[P_TYPE, P_FB_ID, P_IN_FENCE, P_CRTC_ID, P_CRTC_X, P_CRTC_Y, P_CRTC_W, P_CRTC_H, P_SRC_X, P_SRC_Y, P_SRC_W, P_SRC_H, P_DAMAGE],
        CURSOR => &[P_TYPE, P_FB_ID, P_IN_FENCE, P_CRTC_ID, P_CRTC_X, P_CRTC_Y, P_CRTC_W, P_CRTC_H, P_SRC_X, P_SRC_Y, P_SRC_W, P_SRC_H, P_HOT_X, P_HOT_Y],
        CRTC => &[P_ACTIVE, P_MODE_ID, P_OUT_FENCE, P_VRR],
        CONN => &[P_DPMS, P_LINK, P_NONDESKTOP, P_TILE, P_CRTC_ID],
        _ => &[],
    }
}

/// The primary plane's formats, then the cursor's (`virtgpu_plane.c`).
const PRIMARY_FORMATS: [u32; 8] = [0x3432_5258, 0x3432_5241, 0x3432_5842, 0x3432_4142, 0x3432_5852, 0x3432_4152, 0x3432_4258, 0x3432_4241];
const CURSOR_FORMATS: [u32; 1] = [0x3432_5241];

/// The fake mmap offsets: from page 0x100000 (4 GiB), 0xfffff * 256 pages.
const OFFSET_START: u64 = 0x1_0000_0000;
const OFFSET_SIZE: u64 = 0xfffff * 256 * 4096;
const PAGE: u64 = 4096;

// `drm_ioctl`'s permission flags.
const AUTH: u8 = 1;
const MASTER: u8 = 2;
const ROOT: u8 = 4;
const RENDER: u8 = 0x20;

/// The ioctl table (`drm_ioctls` and virtio's): the command it was
/// declared with, and its flags.
fn entry(nr: u32) -> Option<(u32, u8)> {
    Some(match nr {
        0x00 => (0xc040_6400, RENDER),
        0x01 => (0xc010_6401, 0),
        0x02 => (0x8004_6402, 0),
        0x05 => (0xc028_6405, 0),
        0x06 => (0x80f8_6406, 0),
        0x07 => (0xc010_6407, MASTER),
        0x09 => (0x4008_6409, RENDER),
        0x0a => (0xc008_640a, AUTH),
        0x0b => (0xc010_640b, AUTH),
        0x0c => (0xc010_640c, RENDER),
        0x0d => (0x4010_640d, 0),
        0x10 => (0x4010_6410, AUTH | MASTER | ROOT),
        0x11 => (0x4004_6411, MASTER),
        0x12 => (0xc004_6412, AUTH | MASTER | ROOT),
        0x13 => (0xc004_6413, AUTH | MASTER | ROOT),
        0x1e => (0x0000_641e, 0),
        0x1f => (0x0000_641f, 0),
        0x27 => (0xc004_6427, AUTH | MASTER | ROOT),
        0x28 => (0xc004_6428, AUTH | MASTER | ROOT),
        0x2c => (0x4008_642c, AUTH),
        0x2d => (0xc00c_642d, RENDER),
        0x2e => (0xc00c_642e, RENDER),
        0x3a => (0xc018_643a, 0),
        0x3b => (0xc018_643b, 0),
        0x3c => (0xc018_643c, 0),
        0x3f => (0x4018_643f, AUTH | MASTER | ROOT),
        0xa0 => (0xc040_64a0, 0),
        0xa1 => (0xc068_64a1, 0),
        0xa2 => (0xc068_64a2, MASTER),
        0xa3 => (0xc01c_64a3, MASTER),
        0xa4 => (0xc020_64a4, 0),
        0xa5 => (0xc020_64a5, MASTER),
        0xa6 => (0xc014_64a6, 0),
        0xa7 => (0xc050_64a7, 0),
        0xa8 => (0xc048_64a8, MASTER),
        0xa9 => (0xc048_64a9, MASTER),
        0xaa => (0xc040_64aa, 0),
        0xab => (0xc010_64ab, MASTER),
        0xac => (0xc010_64ac, 0),
        0xad => (0xc01c_64ad, 0),
        0xae => (0xc01c_64ae, 0),
        0xaf => (0xc004_64af, 0),
        0xb0 => (0xc018_64b0, MASTER),
        0xb1 => (0xc018_64b1, MASTER),
        0xb2 => (0xc020_64b2, RENDER),
        0xb3 => (0xc010_64b3, RENDER),
        0xb4 => (0xc004_64b4, RENDER),
        0xb5 => (0xc010_64b5, 0),
        0xb6 => (0xc020_64b6, 0),
        0xb7 => (0xc030_64b7, MASTER),
        0xb8 => (0xc068_64b8, 0),
        0xb9 => (0xc020_64b9, 0),
        0xba => (0xc018_64ba, MASTER),
        0xbb => (0xc024_64bb, MASTER),
        0xbc => (0xc038_64bc, MASTER),
        0xbd => (0xc010_64bd, 0),
        0xbe => (0xc004_64be, 0),
        0xbf => (0xc008_64bf, RENDER),
        0xc0 => (0xc008_64c0, RENDER),
        0xc1 => (0xc018_64c1, RENDER),
        0xc2 => (0xc018_64c2, RENDER),
        0xc3 => (0xc028_64c3, RENDER),
        0xc4 => (0xc010_64c4, RENDER),
        0xc5 => (0xc010_64c5, RENDER),
        0xc6 => (0xc018_64c6, MASTER),
        0xc7 => (0xc010_64c7, MASTER),
        0xc8 => (0xc010_64c8, MASTER),
        0xc9 => (0xc004_64c9, MASTER),
        0xca => (0xc030_64ca, RENDER),
        0xcb => (0xc018_64cb, RENDER),
        0xcc => (0xc020_64cc, RENDER),
        0xcd => (0xc018_64cd, RENDER),
        0xce => (0xc068_64ce, 0),
        0xcf => (0xc018_64cf, RENDER),
        0xd0 => (0xc008_64d0, 0),
        0xd1 => (0xc010_64d1, RENDER),
        0xd2 => (0xc008_64d2, RENDER),
        // virtio's own, 0x41 to 0x4b, all for render clients too.
        0x41 => (0xc010_6441, RENDER),
        0x42 => (0xc040_6442, RENDER),
        0x43 => (0xc010_6443, RENDER),
        0x44 => (0xc038_6444, RENDER),
        0x45 => (0xc010_6445, RENDER),
        0x46 => (0xc02c_6446, RENDER),
        0x47 => (0xc02c_6447, RENDER),
        0x48 => (0xc008_6448, RENDER),
        0x49 => (0xc018_6449, RENDER),
        0x4a => (0xc030_644a, RENDER),
        0x4b => (0xc010_644b, RENDER),
        _ => return None,
    })
}

/// Says once, per kind, that a request Linux's driver answers is not
/// answered here.
fn not_here(what: &str) {
    static SAID: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if !said.iter().any(|s| s == what) {
        said.push(what.to_string());
        eprintln!("[gex] virtio_gpu: {what} is not implemented -> EINVAL");
    }
}

/// A buffer object: its bytes, its fake mmap offset and its host resource
/// id. Handles, framebuffers, its dma-buf and mappings hold it.
#[derive(Debug)]
pub struct Bo {
    id: u64,
    res: u32,
    size: u64,
    start: u64,
    data: Mutex<Vec<u8>>,
    /// Changes to the bytes, from 1: what mappings of it catch up by.
    changes: AtomicU64,
    /// `handle_count`: handles in any file, and framebuffers made while
    /// it had one. At 0 the object forgets its dma-buf.
    handles: AtomicU32,
    /// `obj->dma_buf`: the dma-buf it was exported as, while it has handles.
    dmabuf: Mutex<Option<Arc<OpenFile>>>,
}

impl Drop for Bo {
    fn drop(&mut self) {
        // Not waited for: a lookup holding the lock may be what let go of
        // the last reference. A dead entry left is passed over and swept.
        if let Some(mut offs) = gpu().and_then(|g| g.offsets.try_lock().ok()) {
            offs.remove(&self.start);
        }
    }
}

impl Bo {
    fn read(&self, at: u64, buf: &mut [u8]) -> u64 {
        let d = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let at = (at as usize).min(d.len());
        let n = buf.len().min(d.len() - at);
        buf[..n].copy_from_slice(&d[at..at + n]);
        n as u64
    }

    fn write(&self, at: u64, buf: &[u8]) -> u64 {
        let mut d = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let at = (at as usize).min(d.len());
        let n = buf.len().min(d.len() - at);
        if d[at..at + n] != buf[..n] {
            d[at..at + n].copy_from_slice(&buf[..n]);
            self.changes.fetch_add(1, Relaxed);
            if let Some(g) = gpu() {
                g.changes.fetch_add(1, Relaxed);
            }
        }
        n as u64
    }

    fn handle_get(&self) {
        self.handles.fetch_add(1, Relaxed);
    }

    /// One handle fewer; the dma-buf it no longer keeps, to drop outside
    /// any lock.
    fn handle_put(&self) -> Option<Arc<OpenFile>> {
        if self.handles.fetch_sub(1, Relaxed) == 1 {
            return self.dmabuf.lock().unwrap_or_else(|e| e.into_inner()).take();
        }
        None
    }
}

/// A property blob: its bytes and the file that made it, while it holds it.
struct Blob {
    data: Vec<u8>,
    owner: Option<u64>,
}

/// A framebuffer.
struct Fb {
    width: u32,
    height: u32,
    format: u32,
    pitches: [u32; 4],
    offsets: [u32; 4],
    bo: Arc<Bo>,
    /// Whether it holds a handle reference on `bo`.
    holds_handle: bool,
    owner: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct PlaneSt {
    fb: u32,
    crtc: u32,
    crtc_x: i32,
    crtc_y: i32,
    crtc_w: u32,
    crtc_h: u32,
    src: [u32; 4],
    damage: u32,
    hot_x: i32,
    hot_y: i32,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct CrtcSt {
    active: bool,
    enable: bool,
    mode: Option<[u8; 68]>,
    mode_blob: u32,
    vrr: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct ConnSt {
    crtc: u32,
    link: u64,
}

/// The atomic state: the two planes, the CRTC, the connector.
#[derive(Clone, Debug, Default, PartialEq)]
struct Kms {
    planes: [PlaneSt; 2],
    crtc: CrtcSt,
    conn: ConnSt,
}

struct State {
    kms: Kms,
    /// `connector->dpms`, which a modeset sets.
    dpms: u64,
    /// Whether the master has probed the connector: then connected, with
    /// its modes.
    probed: bool,
    modes: Vec<[u8; 68]>,
    blobs: BTreeMap<u32, Blob>,
    fbs: BTreeMap<u32, Fb>,
    /// The current master, by file.
    master: Option<u64>,
    /// Magic numbers handed out (`GET_MAGIC`), to the file they name.
    magics: BTreeMap<u32, u64>,
    files: HashMap<u64, Weak<DrmFile>>,
    fence_ctx: u64,
    fence_seq: u64,
    last_frame: Option<std::time::Instant>,
}

impl State {
    /// The lowest free mode-object id (`idr_alloc(.., 1, 0)`).
    fn new_id(&self) -> u32 {
        let mut id = FIRST_FREE;
        while self.blobs.contains_key(&id) || self.fbs.contains_key(&id) {
            id += 1;
        }
        id
    }

    /// Blobs and framebuffers nobody holds go, and their ids with them.
    fn sweep(&mut self) -> Vec<Arc<OpenFile>> {
        let k = &self.kms;
        let blob_used = |id: &u32| k.crtc.mode_blob == *id || k.planes.iter().any(|p| p.damage == *id);
        self.blobs.retain(|id, b| b.owner.is_some() || blob_used(id));
        let fb_used = |id: &u32| k.planes.iter().any(|p| p.fb == *id);
        let mut dropped = Vec::new();
        let gone: Vec<u32> = self.fbs.iter().filter(|(id, f)| f.owner.is_none() && !fb_used(id)).map(|(id, _)| *id).collect();
        for id in gone {
            if let Some(f) = self.fbs.remove(&id) {
                if f.holds_handle {
                    dropped.extend(f.bo.handle_put());
                }
            }
        }
        dropped
    }
}

/// The device.
pub struct Gpu {
    width: u32,
    height: u32,
    st: Mutex<State>,
    /// The objects by fake offset, which allocation and mappings find.
    offsets: Mutex<BTreeMap<u64, Weak<Bo>>>,
    /// The host resource ids' count (`virglhack`): the first is 2.
    res: AtomicU32,
    next_bo: AtomicU64,
    next_file: AtomicU64,
    dmabuf_ino: AtomicU64,
    /// Changes to any object's bytes, from 1.
    changes: AtomicU64,
    frame: Option<std::path::PathBuf>,
}

/// The device, when there is one (`GEX_VIRTIO_GPU=<w>x<h>`).
pub fn gpu() -> Option<&'static Gpu> {
    static GPU: OnceLock<Option<Gpu>> = OnceLock::new();
    GPU.get_or_init(|| {
        let v = std::env::var("GEX_VIRTIO_GPU").ok()?;
        let (w, h) = v.split_once('x')?;
        Some(Gpu {
            width: w.trim().parse().ok()?,
            height: h.trim().parse().ok()?,
            st: Mutex::new(State {
                kms: Kms::default(),
                dpms: 0,
                probed: false,
                modes: Vec::new(),
                blobs: BTreeMap::new(),
                fbs: BTreeMap::new(),
                master: None,
                magics: BTreeMap::new(),
                files: HashMap::new(),
                fence_ctx: crate::syncfile::context_alloc(),
                fence_seq: 0,
                last_frame: None,
            }),
            offsets: Mutex::new(BTreeMap::new()),
            res: AtomicU32::new(0),
            next_bo: AtomicU64::new(1),
            next_file: AtomicU64::new(1),
            dmabuf_ino: AtomicU64::new(0),
            changes: AtomicU64::new(1),
            frame: std::env::var_os("GEX_VIRTIO_GPU_FRAME").map(Into::into),
        })
    })
    .as_ref()
}

/// The device nodes a kernel with the device has: (name, minor).
pub fn minors() -> &'static [(&'static str, u32)] {
    if gpu().is_some() {
        &[("renderD128", 128), ("card0", 0)]
    } else {
        &[]
    }
}

impl Gpu {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new object of `size` bytes, with its offset (best fit, as
    /// `drm_mm_insert_node` places it) and resource id.
    fn new_bo(&self, size: u64) -> Result<Arc<Bo>, Errno> {
        let pages = size / PAGE;
        let mut offs = self.offsets.lock().unwrap_or_else(|e| e.into_inner());
        offs.retain(|_, w| w.strong_count() > 0);
        let mut best: Option<(u64, u64)> = None;
        let mut at = OFFSET_START;
        let mut consider = |hole_start: u64, hole_end: u64| {
            let len = (hole_end - hole_start) / PAGE;
            if len >= pages && best.is_none_or(|(_, l)| len < l) {
                best = Some((hole_start, len));
            }
        };
        for (&s, w) in offs.iter() {
            if s > at {
                consider(at, s);
            }
            at = s + w.upgrade().map_or(0, |b| b.size);
        }
        consider(at, OFFSET_START + OFFSET_SIZE);
        let (start, _) = best.ok_or(Errno::ENOSPC)?;
        let res = self.res.fetch_add(1, Relaxed) + 2;
        let bo = Arc::new(Bo {
            id: self.next_bo.fetch_add(1, Relaxed),
            res,
            size,
            start,
            data: Mutex::new(vec![0; size as usize]),
            changes: AtomicU64::new(1),
            handles: AtomicU32::new(0),
            dmabuf: Mutex::new(None),
        });
        offs.insert(start, Arc::downgrade(&bo));
        Ok(bo)
    }

    /// The object whose bytes include fake offset `off`.
    fn bo_at(&self, off: u64) -> Option<Arc<Bo>> {
        let offs = self.offsets.lock().unwrap_or_else(|e| e.into_inner());
        let (_, w) = offs.range(..=off).next_back()?;
        w.upgrade().filter(|b| off < b.start + b.size)
    }

    /// What is scanned out: the primary plane's framebuffer's object, the
    /// region shown, its pitch and offset and format, while the CRTC is
    /// active and the plane shows something.
    pub fn scanout(&self) -> Option<(Arc<Bo>, u32, u32, u32, u32, u32)> {
        let st = self.lock();
        let k = &st.kms;
        let p = &k.planes[0];
        if !k.crtc.active || p.fb == 0 || p.crtc != CRTC {
            return None;
        }
        let fb = st.fbs.get(&p.fb)?;
        Some((Arc::clone(&fb.bo), p.src[2] >> 16, p.src[3] >> 16, fb.pitches[0], fb.offsets[0], fb.format))
    }

    /// `GEX_VIRTIO_GPU_FRAME`: the scanout as a PPM, at most once a second.
    fn write_frame(&self) {
        let Some(path) = &self.frame else { return };
        {
            let mut st = self.lock();
            if st.last_frame.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(1)) {
                return;
            }
            st.last_frame = Some(std::time::Instant::now());
        }
        let Some((bo, w, h, pitch, offset, format)) = self.scanout() else { return };
        // Byte positions of red, green and blue in a pixel, by format
        // (little-endian words: XRGB8888 is B, G, R, X in memory).
        let (r, g, b) = match format {
            0x3432_5258 | 0x3432_5241 => (2, 1, 0),
            0x3432_4258 | 0x3432_4241 => (0, 1, 2),
            0x3432_5842 | 0x3432_4142 => (1, 2, 3),
            0x3432_5852 | 0x3432_4152 => (3, 2, 1),
            _ => return,
        };
        let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
        let mut row = vec![0u8; w as usize * 4];
        for y in 0..h as u64 {
            bo.read(offset as u64 + y * pitch as u64, &mut row);
            for px in row.chunks_exact(4) {
                out.extend_from_slice(&[px[r], px[g], px[b]]);
            }
        }
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, &out).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// An open DRM node.
pub struct DrmFile {
    id: u64,
    render: bool,
    node: Option<NodeMeta>,
    f: Mutex<FileSt>,
    events: Mutex<VecDeque<[u8; 32]>>,
    /// The object `may_map` found, for the `map_hold` that follows it.
    pending_map: Mutex<Vec<(std::thread::ThreadId, Arc<Bo>)>>,
}

impl std::fmt::Debug for DrmFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DrmFile({}{})", if self.render { "renderD" } else { "card" }, self.id)
    }
}

#[derive(Default)]
struct FileSt {
    handles: BTreeMap<u32, Arc<Bo>>,
    /// The prime table: the handle a dma-buf (by its object) has here.
    prime: HashMap<u64, u32>,
    universal: bool,
    atomic: bool,
    aspect: bool,
    hotspot: bool,
    stereo: bool,
    writeback: bool,
    is_master: bool,
    was_master: bool,
    authenticated: bool,
    blobs: Vec<u32>,
    /// Newest first.
    fbs: Vec<u32>,
    event_space: u32,
    magic: u32,
}

/// What an ioctl needs of its caller.
pub struct Caller<'a> {
    pub fds: &'a FdTable,
    /// `CAP_SYS_ADMIN`.
    pub admin: bool,
    pub pid: i32,
}

/// Open the node of minor `minor`.
pub fn open(minor: u32, node: NodeMeta) -> Option<Arc<dyn FileHandle>> {
    let g = gpu()?;
    let render = match minor {
        0 => false,
        128 => true,
        _ => return None,
    };
    let file = Arc::new(DrmFile {
        id: g.next_file.fetch_add(1, Relaxed),
        render,
        node: Some(node),
        f: Mutex::new(FileSt { event_space: 4096, ..Default::default() }),
        events: Mutex::new(VecDeque::new()),
        pending_map: Mutex::new(Vec::new()),
    });
    let mut st = g.lock();
    st.files.insert(file.id, Arc::downgrade(&file));
    // `drm_master_open`: the primary node's first opener, while there is
    // no master, becomes it.
    if !render && st.master.is_none() {
        st.master = Some(file.id);
        let mut f = file.f.lock().unwrap();
        f.is_master = true;
        f.was_master = true;
        f.authenticated = true;
    }
    drop(st);
    Some(file)
}

impl Drop for DrmFile {
    /// `drm_file_free`: its framebuffers removed (planes showing them
    /// disabled), its blobs let go, its handles closed, its mastership
    /// dropped.
    fn drop(&mut self) {
        let Some(g) = gpu() else { return };
        let f = std::mem::take(&mut *self.f.lock().unwrap_or_else(|e| e.into_inner()));
        let mut dropped = Vec::new();
        {
            let mut st = g.lock();
            for id in &f.fbs {
                remove_fb(&mut st, *id);
            }
            for id in &f.blobs {
                if let Some(b) = st.blobs.get_mut(id) {
                    b.owner = None;
                }
            }
            if st.master == Some(self.id) {
                st.master = None;
            }
            st.magics.retain(|_, f| *f != self.id);
            st.files.remove(&self.id);
            dropped.extend(st.sweep());
        }
        for bo in f.handles.values() {
            dropped.extend(bo.handle_put());
        }
        drop(f);
        drop(dropped);
    }
}

/// `atomic_remove_fb`'s effect on this driver, and the file's reference
/// let go: every plane showing it is disabled.
fn remove_fb(st: &mut State, id: u32) {
    if let Some(fb) = st.fbs.get_mut(&id) {
        fb.owner = None;
    }
    for p in st.kms.planes.iter_mut() {
        if p.fb == id {
            p.fb = 0;
            p.crtc = 0;
        }
    }
}

// Little helpers over an ioctl's kernel copy.
fn get32(k: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(k[o..o + 4].try_into().unwrap())
}
fn get64(k: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(k[o..o + 8].try_into().unwrap())
}
fn put32(k: &mut [u8], o: usize, v: u32) {
    k[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(k: &mut [u8], o: usize, v: u64) {
    k[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

impl DrmFile {
    fn fl(&self) -> std::sync::MutexGuard<'_, FileSt> {
        self.f.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_current_master(&self, st: &State) -> bool {
        st.master == Some(self.id) && self.fl().is_master
    }

    /// A new handle for `bo` (lowest free from 1); the object counts it.
    fn new_handle(&self, f: &mut FileSt, bo: &Arc<Bo>) -> u32 {
        let mut h = 1;
        while f.handles.contains_key(&h) {
            h += 1;
        }
        bo.handle_get();
        f.handles.insert(h, Arc::clone(bo));
        h
    }

    /// `drm_ioctl`: the table, the sizes, the permissions, the handler,
    /// and the copy back (which happens whatever the handler said).
    pub fn ioctl(&self, cx: &Caller<'_>, m: &mut GuestMem<'_>, req: u64, arg: u64) -> SysResult {
        let req = req as u32;
        let Some(g) = gpu() else { return Err(Errno::ENODEV) };
        if (req >> 8) & 0xff != 0x64 {
            return Err(Errno::ENOTTY);
        }
        let nr = req & 0xff;
        let Some((tcmd, flags)) = entry(nr) else { return Err(Errno::EINVAL) };
        let size = |c: u32| ((c >> 16) & 0x3fff) as usize;
        let (dir, tdir) = (req >> 30, tcmd >> 30);
        let in_size = if dir & 1 != 0 && tdir & 1 != 0 { size(req) } else { 0 };
        let out_size = if dir & 2 != 0 && tdir & 2 != 0 { size(req) } else { 0 };
        let mut k = vec![0u8; in_size.max(out_size).max(size(tcmd))];
        if in_size > 0 {
            k[..in_size].copy_from_slice(m.read(arg, in_size)?);
        }
        let r = self.permit(g, cx, flags).and_then(|()| self.handle(g, cx, m, nr, &mut k));
        if out_size > 0 {
            m.write(arg, &k[..out_size])?;
        }
        r
    }

    /// `drm_ioctl_permit`.
    fn permit(&self, g: &Gpu, cx: &Caller<'_>, flags: u8) -> Result<(), Errno> {
        if flags & ROOT != 0 && !cx.admin {
            return Err(Errno::EACCES);
        }
        if flags & AUTH != 0 && !self.render && !self.fl().authenticated && !cx.admin {
            return Err(Errno::EACCES);
        }
        if flags & MASTER != 0 && !self.is_current_master(&g.lock()) {
            return Err(Errno::EACCES);
        }
        if flags & RENDER == 0 && self.render {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    fn handle(&self, g: &Gpu, cx: &Caller<'_>, m: &mut GuestMem<'_>, nr: u32, k: &mut [u8]) -> SysResult {
        match nr {
            0x00 => self.version(m, k),
            0x01 => {
                // GET_UNIQUE: the master's unique name, which nothing set.
                put64(k, 0, 0);
                Ok(0)
            }
            0x02 => self.get_magic(g, k),
            0x05 => {
                // GET_CLIENT: only the caller, by index 0.
                if get32(k, 0) != 0 {
                    return Err(Errno::EINVAL);
                }
                put32(k, 4, self.fl().authenticated as u32);
                put64(k, 8, cx.pid as u64);
                put64(k, 16, 65534);
                put64(k, 24, 0);
                put64(k, 32, 0);
                Ok(0)
            }
            0x06 => {
                k.fill(0);
                Ok(0)
            }
            0x09 => self.gem_close(get32(k, 0)),
            0x0c => self.get_cap(k),
            0x0d => self.set_client_cap(k),
            0x10 => Err(Errno::EINVAL),
            0x11 => self.auth_magic(g, get32(k, 0)),
            0x12 | 0x13 | 0x27 | 0x28 | 0x2c | 0x3f | 0xa8 | 0xa9 => Ok(0),
            0x1e => self.set_master(g, cx),
            0x1f => self.drop_master(g, cx),
            0x2d => self.prime_handle_to_fd(cx, k),
            0x2e => self.prime_fd_to_handle(cx, k),
            0x3a | 0x3b | 0x3c => Err(Errno::EOPNOTSUPP),
            0xa0 => self.get_resources(g, m, k),
            0xa1 => self.get_crtc(g, k),
            0xa4 => {
                // GETGAMMA: a gamma size of 0, so nothing to copy.
                if get32(k, 0) != CRTC {
                    return Err(Errno::ENOENT);
                }
                if get32(k, 4) != 0 {
                    return Err(Errno::EINVAL);
                }
                Ok(0)
            }
            0xa5 => {
                if get32(k, 0) != CRTC {
                    return Err(Errno::ENOENT);
                }
                Err(Errno::ENOSYS)
            }
            0xa6 => self.get_encoder(g, k),
            0xa7 => self.get_connector(g, m, k),
            0xaa => self.get_property(m, k),
            0xac => self.get_blob(g, m, k),
            0xae => self.addfb(g, k),
            0xaf => self.rmfb(g, get32(k, 0)),
            0xb2 => self.create_dumb(g, k),
            0xb3 => {
                let off = self.map_offset(get32(k, 0))?;
                put64(k, 8, off);
                Ok(0)
            }
            0xb4 => self.gem_close(get32(k, 0)),
            0xb5 => self.get_plane_resources(m, k),
            0xb6 => self.get_plane(g, m, k),
            0xb8 => self.addfb2(g, k),
            0xb9 => self.obj_get_properties(g, m, k),
            0xbc => self.atomic(g, cx, m, k),
            0xbd => self.create_blob(g, m, k),
            0xbe => self.destroy_blob(g, get32(k, 0)),
            0xd0 => {
                // CLOSEFB: the file's reference only; planes keep it.
                if get32(k, 4) != 0 {
                    return Err(Errno::EINVAL);
                }
                let id = get32(k, 0);
                let mut st = g.lock();
                if !st.fbs.contains_key(&id) {
                    return Err(Errno::ENOENT);
                }
                let mut f = self.fl();
                let i = f.fbs.iter().position(|x| *x == id).ok_or(Errno::ENOENT)?;
                f.fbs.remove(i);
                drop(f);
                if let Some(fb) = st.fbs.get_mut(&id) {
                    fb.owner = None;
                }
                let dropped = st.sweep();
                drop(st);
                drop(dropped);
                Ok(0)
            }
            // virtio's.
            0x41 => {
                let off = self.map_offset(get32(k, 8))?;
                put64(k, 0, off);
                Ok(0)
            }
            0x42 | 0x46 => Err(Errno::ENOSYS),
            0x43 => self.getparam(m, k),
            0x45 => {
                // RESOURCE_INFO.
                let bo = self.fl().handles.get(&get32(k, 0)).cloned().ok_or(Errno::ENOENT)?;
                put32(k, 8, bo.size as u32);
                put32(k, 4, bo.res);
                Ok(0)
            }
            0x47 => {
                // TRANSFER_TO_HOST: the host is this kernel, whose bytes
                // the object's are.
                if !self.fl().handles.contains_key(&get32(k, 0)) {
                    return Err(Errno::ENOENT);
                }
                Ok(0)
            }
            0x48 => {
                // WAIT: dumb objects carry no fences.
                if !self.fl().handles.contains_key(&get32(k, 0)) {
                    return Err(Errno::ENOENT);
                }
                Ok(0)
            }
            0x49 => Err(Errno::ENOSYS),
            0x4a | 0x4b => Err(Errno::EINVAL),
            0x44 => {
                not_here("VIRTGPU_RESOURCE_CREATE");
                Err(Errno::EINVAL)
            }
            0x07 => {
                not_here("SET_VERSION");
                Err(Errno::EINVAL)
            }
            0x0a | 0x0b => {
                not_here("GEM flink names");
                Err(Errno::EINVAL)
            }
            0xa2 | 0xa3 | 0xab | 0xb0 | 0xb1 | 0xb7 | 0xba | 0xbb => {
                not_here("legacy mode setting (SETCRTC, SETPLANE, CURSOR, PAGE_FLIP, DIRTYFB, SETPROPERTY)");
                Err(Errno::EINVAL)
            }
            0xad | 0xce => {
                not_here("GETFB and GETFB2");
                Err(Errno::EINVAL)
            }
            0xbf..=0xc5 | 0xca..=0xcd | 0xcf => {
                not_here("syncobjs");
                Err(Errno::EINVAL)
            }
            0xc6..=0xc9 => {
                not_here("leases");
                Err(Errno::EINVAL)
            }
            0xd1 => {
                not_here("SET_CLIENT_NAME");
                Err(Errno::EINVAL)
            }
            0xd2 => {
                not_here("GEM_CHANGE_HANDLE");
                Err(Errno::EINVAL)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// VERSION: 0.1.0, "virtio_gpu", "0", "virtio GPU"; each string copied
    /// up to the caller's length, unterminated, and its length said.
    fn version(&self, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        put32(k, 0, 0);
        put32(k, 4, 1);
        put32(k, 8, 0);
        for (at, s) in [(16, "virtio_gpu"), (32, "0"), (48, "virtio GPU")] {
            let (len, ptr) = (get64(k, at), get64(k, at + 8));
            let n = (s.len() as u64).min(len) as usize;
            put64(k, at, s.len() as u64);
            if n > 0 && ptr != 0 {
                m.write(ptr, &s.as_bytes()[..n])?;
            }
        }
        Ok(0)
    }

    fn get_cap(&self, k: &mut [u8]) -> SysResult {
        let cap = get64(k, 0);
        put64(k, 8, 0);
        let v = match cap {
            0x1 | 0x2 => 1,
            0x3 | 0x4 | 0x7 => 0,
            0x5 => 3,
            0x6 => 1,
            0x8 | 0x9 => 64,
            0x10 | 0x11 | 0x15 => 0,
            0x12 | 0x13 | 0x14 => 1,
            _ => return Err(Errno::EINVAL),
        };
        put64(k, 8, v);
        Ok(0)
    }

    fn set_client_cap(&self, k: &mut [u8]) -> SysResult {
        let (cap, v) = (get64(k, 0), get64(k, 8));
        let mut f = self.fl();
        match cap {
            1 if v <= 1 => f.stereo = v != 0,
            2 if v <= 1 => f.universal = v != 0,
            3 if v <= 2 => {
                f.atomic = v != 0;
                f.universal = v != 0;
                f.aspect = v != 0;
            }
            4 if v <= 1 => f.aspect = v != 0,
            5 | 6 | 7 if !f.atomic => return Err(Errno::EINVAL),
            5 if v <= 1 => f.writeback = v != 0,
            6 if v <= 1 => f.hotspot = v != 0,
            7 if v <= 1 => return Err(Errno::EOPNOTSUPP),
            _ => return Err(Errno::EINVAL),
        }
        Ok(0)
    }

    fn get_magic(&self, g: &Gpu, k: &mut [u8]) -> SysResult {
        let mut st = g.lock();
        let mut f = self.fl();
        if f.magic == 0 {
            let mut m = 1;
            while st.magics.contains_key(&m) {
                m += 1;
            }
            st.magics.insert(m, self.id);
            f.magic = m;
        }
        put32(k, 0, f.magic);
        Ok(0)
    }

    fn auth_magic(&self, g: &Gpu, magic: u32) -> SysResult {
        let mut st = g.lock();
        let id = st.magics.remove(&magic).ok_or(Errno::EINVAL)?;
        if let Some(file) = st.files.get(&id).and_then(Weak::upgrade) {
            file.fl().authenticated = true;
        }
        Ok(0)
    }

    /// SET_MASTER (`drm_setmaster_ioctl`): for a file that was master
    /// (taken here as its process's own), or with `CAP_SYS_ADMIN`.
    fn set_master(&self, g: &Gpu, cx: &Caller<'_>) -> SysResult {
        if self.render {
            return Err(Errno::EINVAL);
        }
        let mut st = g.lock();
        let mut f = self.fl();
        if !f.was_master && !cx.admin {
            return Err(Errno::EACCES);
        }
        if st.master == Some(self.id) && f.is_master {
            return Ok(0);
        }
        if st.master.is_some() {
            return Err(Errno::EBUSY);
        }
        st.master = Some(self.id);
        f.is_master = true;
        f.was_master = true;
        f.authenticated = true;
        Ok(0)
    }

    fn drop_master(&self, g: &Gpu, cx: &Caller<'_>) -> SysResult {
        let mut st = g.lock();
        let f = self.fl();
        if !f.was_master && !cx.admin {
            return Err(Errno::EACCES);
        }
        if st.master != Some(self.id) {
            return Err(Errno::EINVAL);
        }
        st.master = None;
        Ok(0)
    }

    fn gem_close(&self, handle: u32) -> SysResult {
        let mut f = self.fl();
        let bo = f.handles.remove(&handle).ok_or(Errno::EINVAL)?;
        f.prime.retain(|_, h| *h != handle);
        drop(f);
        let dropped = bo.handle_put();
        drop(dropped);
        Ok(0)
    }

    /// CREATE_DUMB: the core's checks, then virtio's (32 bits a pixel
    /// only; the pitch and the page-rounded size).
    fn create_dumb(&self, g: &Gpu, k: &mut [u8]) -> SysResult {
        let (h, w, bpp) = (get32(k, 0), get32(k, 4), get32(k, 8));
        if w == 0 || h == 0 || bpp == 0 || bpp > u32::MAX - 8 {
            return Err(Errno::EINVAL);
        }
        let cpp = bpp.div_ceil(8);
        if cpp > u32::MAX / w {
            return Err(Errno::EINVAL);
        }
        let stride = cpp * w;
        if h > u32::MAX / stride {
            return Err(Errno::EINVAL);
        }
        let size = h * stride;
        if size > 0xffff_f000 {
            return Err(Errno::EINVAL);
        }
        put32(k, 16, 0);
        put32(k, 20, 0);
        put64(k, 24, 0);
        if bpp != 32 {
            return Err(Errno::EINVAL);
        }
        let pitch = w * 4;
        let size = (pitch as u64 * h as u64).div_ceil(PAGE) * PAGE;
        put64(k, 24, size);
        let bo = g.new_bo(size)?;
        let handle = {
            let mut f = self.fl();
            self.new_handle(&mut f, &bo)
        };
        put32(k, 16, handle);
        put32(k, 20, pitch);
        Ok(0)
    }

    /// `drm_gem_dumb_map_offset`.
    fn map_offset(&self, handle: u32) -> Result<u64, Errno> {
        self.fl().handles.get(&handle).map(|b| b.start).ok_or(Errno::ENOENT)
    }

    /// PRIME_HANDLE_TO_FD: the object's one dma-buf (made at its first
    /// export, read-write if that export asked), in a new descriptor.
    fn prime_handle_to_fd(&self, cx: &Caller<'_>, k: &mut [u8]) -> SysResult {
        const CLOEXEC: u32 = 0o2000000;
        const RDWR: u32 = 2;
        let (handle, flags) = (get32(k, 0), get32(k, 4));
        if flags & !(CLOEXEC | RDWR) != 0 {
            return Err(Errno::EINVAL);
        }
        let bo = self.fl().handles.get(&handle).cloned().ok_or(Errno::ENOENT)?;
        let file = {
            let mut d = bo.dmabuf.lock().unwrap_or_else(|e| e.into_inner());
            match &*d {
                Some(f) => Arc::clone(f),
                None => {
                    let g = gpu().ok_or(Errno::ENODEV)?;
                    let ino = g.dmabuf_ino.fetch_add(1, Relaxed) + 1;
                    let buf = Arc::new(DmaBuf { bo: Arc::clone(&bo), ino, name: Mutex::new(String::new()) });
                    let rw = flags & RDWR != 0;
                    let f = OpenFile::new(buf, "/dmabuf:".into(), if rw { crate::fs::oflags::O_RDWR } else { crate::fs::oflags::O_RDONLY }, true, rw);
                    *d = Some(Arc::clone(&f));
                    f
                }
            }
        };
        self.fl().prime.insert(bo.id, handle);
        let fd = cx.fds.insert(file, flags & CLOEXEC != 0)?;
        put32(k, 8, fd as u32);
        Ok(0)
    }

    /// PRIME_FD_TO_HANDLE: a dma-buf of this device is its own object;
    /// the handle the file has for it from the prime table, else a new one.
    fn prime_fd_to_handle(&self, cx: &Caller<'_>, k: &mut [u8]) -> SysResult {
        let fd = get32(k, 8) as i32;
        let file = cx.fds.get(fd).map_err(|_| Errno::EBADF)?;
        let buf = Arc::clone(&file.handle).as_dmabuf().ok_or(Errno::EINVAL)?;
        let bo = Arc::clone(&buf.bo);
        let mut f = self.fl();
        if let Some(&h) = f.prime.get(&bo.id) {
            put32(k, 0, h);
            return Ok(0);
        }
        let h = self.new_handle(&mut f, &bo);
        f.prime.insert(bo.id, h);
        drop(f);
        let mut d = bo.dmabuf.lock().unwrap_or_else(|e| e.into_inner());
        if d.is_none() {
            *d = Some(file);
        }
        put32(k, 0, h);
        Ok(0)
    }

    /// GETRESOURCES: this file's framebuffers (newest first), the CRTC,
    /// the connector, the encoder; each list copied as far as the caller's
    /// count allows, and its count said.
    fn get_resources(&self, g: &Gpu, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let fbs = self.fl().fbs.clone();
        let _ = g;
        let lists: [(usize, usize, &[u32]); 4] = [(0, 32, &fbs), (8, 36, &[CRTC]), (24, 44, &[ENC]), (16, 40, &[CONN])];
        put32(k, 48, 32);
        put32(k, 52, 8192);
        put32(k, 56, 32);
        put32(k, 60, 8192);
        for (ptr_at, count_at, ids) in lists {
            let (ptr, have) = (get64(k, ptr_at), get32(k, count_at));
            for (i, id) in ids.iter().enumerate() {
                if (i as u32) < have {
                    m.write_u32(ptr + i as u64 * 4, *id)?;
                }
            }
            put32(k, count_at, ids.len() as u32);
        }
        Ok(0)
    }

    fn get_crtc(&self, g: &Gpu, k: &mut [u8]) -> SysResult {
        if get32(k, 12) != CRTC {
            return Err(Errno::ENOENT);
        }
        let st = g.lock();
        let kms = &st.kms;
        put32(k, 28, 0);
        let primary = &kms.planes[0];
        put32(k, 16, primary.fb);
        put32(k, 20, primary.src[0] >> 16);
        put32(k, 24, primary.src[1] >> 16);
        match (&kms.crtc.mode, kms.crtc.enable) {
            (Some(mode), true) => {
                let mut mode = *mode;
                if !self.fl().aspect {
                    let flags = u32::from_le_bytes(mode[28..32].try_into().unwrap()) & !(0xf << 19);
                    mode[28..32].copy_from_slice(&flags.to_le_bytes());
                }
                k[36..104].copy_from_slice(&mode);
                put32(k, 32, 1);
            }
            _ => put32(k, 32, 0),
        }
        Ok(0)
    }

    fn get_encoder(&self, g: &Gpu, k: &mut [u8]) -> SysResult {
        if get32(k, 0) != ENC {
            return Err(Errno::ENOENT);
        }
        let routed = g.lock().kms.conn.crtc != 0;
        put32(k, 4, 5);
        put32(k, 8, if routed { CRTC } else { 0 });
        put32(k, 12, 1);
        put32(k, 16, 1);
        Ok(0)
    }

    /// GETCONNECTOR: the master's call with no room for modes probes it
    /// (connected, the host's size and the DMT modes).
    fn get_connector(&self, g: &Gpu, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        if get32(k, 48) != CONN {
            return Err(Errno::ENOENT);
        }
        if get32(k, 40) >= 1 {
            m.write_u32(get64(k, 0), ENC)?;
        }
        put32(k, 40, 1);
        put32(k, 52, 15);
        put32(k, 56, 1);
        let mut st = g.lock();
        if get32(k, 32) == 0 && self.is_current_master(&st) {
            st.probed = true;
            st.modes = drm_modes::probe(g.width, g.height).iter().map(|m| m.to_umode()).collect();
        }
        put32(k, 64, 0);
        put32(k, 68, 0);
        put32(k, 72, 0);
        put32(k, 60, if st.probed { 1 } else { 3 });
        let n = st.modes.len() as u32;
        if get32(k, 32) >= n && n > 0 {
            let ptr = get64(k, 8);
            for (i, mode) in st.modes.iter().enumerate() {
                m.write(ptr + i as u64 * 68, mode)?;
            }
        }
        put32(k, 32, n);
        put32(k, 44, if st.kms.conn.crtc != 0 { ENC } else { 0 });
        let (props, values) = self.visible(&st, CONN);
        drop(st);
        let have = get32(k, 36);
        let (pp, vp) = (get64(k, 16), get64(k, 24));
        for (i, (id, v)) in props.iter().zip(values.iter()).enumerate() {
            if (i as u32) < have {
                m.write_u32(pp + i as u64 * 4, *id)?;
                m.write_u64(vp + i as u64 * 8, *v)?;
            }
        }
        put32(k, 36, props.len() as u32);
        Ok(0)
    }

    /// An object's properties this file sees (atomic-only ones for an
    /// atomic client), with their values now.
    fn visible(&self, st: &State, obj: u32) -> (Vec<u32>, Vec<u64>) {
        let atomic = self.fl().atomic;
        let mut ids = Vec::new();
        let mut vals = Vec::new();
        for &id in attached(obj) {
            if prop(id).unwrap().flags & ATOMIC != 0 && !atomic {
                continue;
            }
            ids.push(id);
            vals.push(value(st, obj, id));
        }
        (ids, vals)
    }

    fn get_property(&self, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let id = get32(k, 16);
        let p = prop(id).ok_or(Errno::ENOENT)?;
        k[24..56].fill(0);
        k[24..24 + p.name.len()].copy_from_slice(p.name.as_bytes());
        put32(k, 20, p.flags);
        let (vp, have) = (get64(k, 0), get32(k, 56));
        for (i, v) in p.values.iter().enumerate() {
            if (i as u32) < have {
                m.write_u64(vp + i as u64 * 8, *v)?;
            }
        }
        put32(k, 56, p.values.len() as u32);
        if p.flags & ENUM != 0 {
            let (ep, have) = (get64(k, 8), get32(k, 60));
            for (i, (v, name)) in p.enums.iter().enumerate() {
                if (i as u32) < have {
                    let mut e = [0u8; 40];
                    e[0..8].copy_from_slice(&v.to_le_bytes());
                    e[8..8 + name.len()].copy_from_slice(name.as_bytes());
                    m.write(ep + i as u64 * 40, &e)?;
                }
            }
            put32(k, 60, p.enums.len() as u32);
        } else if p.flags & BLOB != 0 {
            put32(k, 60, 0);
        }
        Ok(0)
    }

    fn get_blob(&self, g: &Gpu, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let st = g.lock();
        let b = st.blobs.get(&get32(k, 0)).ok_or(Errno::ENOENT)?;
        if get32(k, 4) as usize == b.data.len() {
            m.write(get64(k, 8), &b.data)?;
        }
        put32(k, 4, b.data.len() as u32);
        Ok(0)
    }

    fn create_blob(&self, g: &Gpu, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let len = get32(k, 8);
        if len == 0 || len as u64 > i32::MAX as u64 - 64 {
            return Err(Errno::EINVAL);
        }
        let data = m.read(get64(k, 0), len as usize)?.to_vec();
        let mut st = g.lock();
        let id = st.new_id();
        st.blobs.insert(id, Blob { data, owner: Some(self.id) });
        self.fl().blobs.push(id);
        put32(k, 12, id);
        Ok(0)
    }

    fn destroy_blob(&self, g: &Gpu, id: u32) -> SysResult {
        let mut st = g.lock();
        if !st.blobs.contains_key(&id) {
            return Err(Errno::ENOENT);
        }
        let mut f = self.fl();
        let i = f.blobs.iter().position(|b| *b == id).ok_or(Errno::EPERM)?;
        f.blobs.remove(i);
        drop(f);
        if let Some(b) = st.blobs.get_mut(&id) {
            b.owner = None;
        }
        let dropped = st.sweep();
        drop(st);
        drop(dropped);
        Ok(0)
    }

    fn get_plane_resources(&self, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let f = self.fl();
        let mut planes = Vec::new();
        if f.universal {
            planes.push(PRIMARY);
            if !(f.atomic && !f.hotspot) {
                planes.push(CURSOR);
            }
        }
        drop(f);
        let (ptr, have) = (get64(k, 0), get32(k, 8));
        for (i, id) in planes.iter().enumerate() {
            if (i as u32) < have {
                m.write_u32(ptr + i as u64 * 4, *id)?;
            }
        }
        put32(k, 8, planes.len() as u32);
        Ok(0)
    }

    fn get_plane(&self, g: &Gpu, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let id = get32(k, 0);
        let (i, formats): (usize, &[u32]) = match id {
            PRIMARY => (0, &PRIMARY_FORMATS),
            CURSOR => (1, &CURSOR_FORMATS),
            _ => return Err(Errno::ENOENT),
        };
        let st = g.lock();
        let p = &st.kms.planes[i];
        put32(k, 4, p.crtc);
        put32(k, 8, p.fb);
        drop(st);
        put32(k, 12, 1);
        put32(k, 16, 0);
        if get32(k, 20) as usize >= formats.len() {
            let ptr = get64(k, 24);
            for (j, f) in formats.iter().enumerate() {
                m.write_u32(ptr + j as u64 * 4, *f)?;
            }
        }
        put32(k, 20, formats.len() as u32);
        Ok(0)
    }

    fn obj_get_properties(&self, g: &Gpu, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let (id, ty) = (get32(k, 20), get32(k, 24));
        let st = g.lock();
        let real = object_type(&st, id).ok_or(Errno::ENOENT)?;
        if ty != 0 && ty != real {
            return Err(Errno::ENOENT);
        }
        if attached(id).is_empty() {
            return Err(Errno::EINVAL);
        }
        let (props, values) = self.visible(&st, id);
        drop(st);
        let (pp, vp, have) = (get64(k, 0), get64(k, 8), get32(k, 16));
        for (i, (p, v)) in props.iter().zip(values.iter()).enumerate() {
            if (i as u32) < have {
                m.write_u32(pp + i as u64 * 4, *p)?;
                m.write_u64(vp + i as u64 * 8, *v)?;
            }
        }
        put32(k, 16, props.len() as u32);
        Ok(0)
    }

    /// ADDFB: the legacy depth and bpp as a format, then ADDFB2.
    fn addfb(&self, g: &Gpu, k: &mut [u8]) -> SysResult {
        let format = match (get32(k, 16), get32(k, 20)) {
            (1, 1) => 0x2020_3143,
            (2, 2) => 0x2020_3243,
            (4, 4) => 0x2020_3443,
            (8, 8) => 0x2020_3843,
            (16, 15) => 0x3531_5258,
            (16, 16) => 0x3631_5652,
            (24, 24) => 0x3432_4752,
            (32, 24) => 0x3432_5258,
            (32, 30) => 0x3033_5258,
            (32, 32) => 0x3432_5241,
            _ => return Err(Errno::EINVAL),
        };
        let mut k2 = [0u8; 104];
        put32(&mut k2, 4, get32(k, 4));
        put32(&mut k2, 8, get32(k, 8));
        put32(&mut k2, 12, format);
        put32(&mut k2, 20, get32(k, 24));
        put32(&mut k2, 36, get32(k, 12));
        self.addfb2(g, &mut k2)?;
        put32(k, 0, get32(&k2, 0));
        Ok(0)
    }

    /// ADDFB2, in the core's order of checks; virtio looks up only the
    /// first plane's handle, and nothing compares the size with the object.
    fn addfb2(&self, g: &Gpu, k: &mut [u8]) -> SysResult {
        let (w, h, format, flags) = (get32(k, 4), get32(k, 8), get32(k, 12), get32(k, 16));
        let handles = [get32(k, 20), get32(k, 24), get32(k, 28), get32(k, 32)];
        let pitches = [get32(k, 36), get32(k, 40), get32(k, 44), get32(k, 48)];
        let offsets = [get32(k, 52), get32(k, 56), get32(k, 60), get32(k, 64)];
        let modifiers = [get64(k, 72), get64(k, 80), get64(k, 88), get64(k, 96)];
        if flags & !3 != 0 || !(32..=8192).contains(&w) || !(32..=8192).contains(&h) || flags & 2 != 0 {
            return Err(Errno::EINVAL);
        }
        let info = format_info(format).ok_or(Errno::EINVAL)?;
        for i in 0..info.planes {
            if handles[i] == 0 {
                return Err(Errno::EINVAL);
            }
            let (pw, ph) = if i == 0 { (w as u64, h as u64) } else { (w.div_ceil(info.hsub) as u64, h.div_ceil(info.vsub) as u64) };
            let min_pitch = pw * info.cpp[i] as u64;
            if min_pitch > u32::MAX as u64 || ph * pitches[i] as u64 + offsets[i] as u64 > u32::MAX as u64 {
                return Err(Errno::ERANGE);
            }
            if (pitches[i] as u64) < min_pitch || modifiers[i] != 0 {
                return Err(Errno::EINVAL);
            }
        }
        if modifiers[info.planes..].iter().any(|m| *m != 0) {
            return Err(Errno::EINVAL);
        }
        let bo = self.fl().handles.get(&handles[0]).cloned().ok_or(Errno::EINVAL)?;
        let holds_handle = bo.handles.load(Relaxed) > 0;
        if holds_handle {
            bo.handle_get();
        }
        let mut st = g.lock();
        let id = st.new_id();
        st.fbs.insert(id, Fb { width: w, height: h, format, pitches, offsets, bo, holds_handle, owner: Some(self.id) });
        self.fl().fbs.insert(0, id);
        put32(k, 0, id);
        Ok(0)
    }

    fn rmfb(&self, g: &Gpu, id: u32) -> SysResult {
        let mut st = g.lock();
        if !st.fbs.contains_key(&id) {
            return Err(Errno::ENOENT);
        }
        let mut f = self.fl();
        let i = f.fbs.iter().position(|x| *x == id).ok_or(Errno::ENOENT)?;
        f.fbs.remove(i);
        drop(f);
        remove_fb(&mut st, id);
        let dropped = st.sweep();
        drop(st);
        drop(dropped);
        Ok(0)
    }

    /// VIRTGPU_GETPARAM: four bytes to the caller's pointer.
    fn getparam(&self, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        let v: u32 = match get64(k, 0) {
            2 => 1,
            1 | 3..=8 => 0,
            _ => return Err(Errno::EINVAL),
        };
        m.write_u32(get64(k, 8), v)?;
        Ok(0)
    }

    /// ATOMIC: the argument checks, the properties in order onto a copy of
    /// the state, the checks of `drm_atomic_check_only` and
    /// `drm_atomic_helper_check` as virtio has them, then (unless only a
    /// test) the new state, its events and its out-fence.
    fn atomic(&self, g: &Gpu, cx: &Caller<'_>, m: &mut GuestMem<'_>, k: &mut [u8]) -> SysResult {
        const EVENT: u32 = 0x1;
        const ASYNC: u32 = 0x2;
        const TEST: u32 = 0x100;
        const ALLOW_MODESET: u32 = 0x400;
        let (flags, count) = (get32(k, 0), get32(k, 4));
        let (objs, counts, props, values) = (get64(k, 8), get64(k, 16), get64(k, 24), get64(k, 32));
        if !self.fl().atomic || flags & !0x703 != 0 || get64(k, 40) != 0 || flags & ASYNC != 0 || (flags & TEST != 0 && flags & EVENT != 0) {
            return Err(Errno::EINVAL);
        }
        let mut st = g.lock();
        let old = st.kms.clone();
        let mut new = old.clone();
        // Which objects are in the state.
        let mut planes_in = [false; 2];
        let mut crtc_in = false;
        let mut conn_in = false;
        let mut out_fence: Option<u64> = None;
        let mut copied = 0u64;
        for i in 0..count as u64 {
            let obj = m.read_u32(objs + i * 4)?;
            if object_type(&st, obj).is_none() || attached(obj).is_empty() {
                return Err(Errno::ENOENT);
            }
            let n = m.read_u32(counts + i * 4)?;
            for _ in 0..n {
                let pid = m.read_u32(props + copied * 4)?;
                if !attached(obj).contains(&pid) {
                    return Err(Errno::ENOENT);
                }
                let v = m.read_u64(values + copied * 8)?;
                copied += 1;
                change_valid(&st, pid, v)?;
                match obj {
                    PRIMARY | CURSOR => {
                        let pi = (obj - PRIMARY) as usize;
                        planes_in[pi] = true;
                        let pl = &mut new.planes[pi];
                        match pid {
                            P_FB_ID => pl.fb = v as u32,
                            // No sync file here is still pending; -1 is none.
                            P_IN_FENCE => {
                                if v as i64 != -1 {
                                    let f = cx.fds.get(v as i32).map_err(|_| Errno::EINVAL)?;
                                    Arc::clone(&f.handle).as_syncfile().ok_or(Errno::EINVAL)?;
                                }
                            }
                            P_CRTC_ID => {
                                pl.crtc = v as u32;
                                crtc_in = true;
                            }
                            P_CRTC_X => pl.crtc_x = v as i32,
                            P_CRTC_Y => pl.crtc_y = v as i32,
                            P_CRTC_W => pl.crtc_w = v as u32,
                            P_CRTC_H => pl.crtc_h = v as u32,
                            P_SRC_X => pl.src[0] = v as u32,
                            P_SRC_Y => pl.src[1] = v as u32,
                            P_SRC_W => pl.src[2] = v as u32,
                            P_SRC_H => pl.src[3] = v as u32,
                            P_DAMAGE => {
                                if v != 0 && st.blobs.get(&(v as u32)).is_none_or(|b| b.data.len() % 16 != 0) {
                                    return Err(Errno::EINVAL);
                                }
                                pl.damage = v as u32;
                            }
                            P_HOT_X if obj == CURSOR => pl.hot_x = v as i32,
                            P_HOT_Y if obj == CURSOR => pl.hot_y = v as i32,
                            _ => return Err(Errno::EINVAL),
                        }
                        if pl.crtc != 0 {
                            crtc_in = true;
                        }
                    }
                    CRTC => {
                        crtc_in = true;
                        let c = &mut new.crtc;
                        match pid {
                            P_ACTIVE => c.active = v != 0,
                            P_MODE_ID => {
                                if v as u32 != c.mode_blob {
                                    c.mode = None;
                                    c.mode_blob = 0;
                                    c.enable = false;
                                    if v != 0 {
                                        let b = st.blobs.get(&(v as u32)).ok_or(Errno::EINVAL)?;
                                        let mode: [u8; 68] = b.data.as_slice().try_into().map_err(|_| Errno::EINVAL)?;
                                        if !drm_modes::umode_valid(&mode) {
                                            return Err(Errno::EINVAL);
                                        }
                                        // `drm_mode_convert_umode` keeps the
                                        // known type bits only.
                                        let mut mode = mode;
                                        let ty = u32::from_le_bytes(mode[32..36].try_into().unwrap()) & drm_modes::TYPE_ALL;
                                        mode[32..36].copy_from_slice(&ty.to_le_bytes());
                                        c.mode = Some(mode);
                                        c.mode_blob = v as u32;
                                        c.enable = true;
                                    }
                                }
                            }
                            P_OUT_FENCE => {
                                if v != 0 {
                                    m.write_u32(v, u32::MAX)?;
                                    out_fence = Some(v);
                                }
                            }
                            P_VRR => c.vrr = v != 0,
                            _ => return Err(Errno::EINVAL),
                        }
                    }
                    CONN => {
                        conn_in = true;
                        match pid {
                            P_CRTC_ID => {
                                new.conn.crtc = v as u32;
                                crtc_in = true;
                            }
                            P_LINK => {
                                if new.conn.link != 0 {
                                    new.conn.link = v;
                                }
                            }
                            _ => return Err(Errno::EINVAL),
                        }
                    }
                    _ => return Err(Errno::ENOENT),
                }
            }
        }
        if old.conn.crtc != 0 && conn_in {
            crtc_in = true;
        }
        let _ = conn_in;
        if flags & EVENT != 0 && !crtc_in {
            return Err(Errno::EINVAL);
        }
        // `drm_atomic_check_only`, first the planes in the state.
        for (i, &inn) in planes_in.iter().enumerate() {
            if inn {
                plane_check(&st, &new.planes[i], i)?;
            }
        }
        // The CRTC.
        if crtc_in {
            if new.crtc.active && !new.crtc.enable {
                return Err(Errno::EINVAL);
            }
            if flags & EVENT != 0 && !old.crtc.active && !new.crtc.active {
                return Err(Errno::EINVAL);
            }
        }
        // `drm_atomic_helper_check_modeset`.
        let mode_changed = match (&old.crtc.mode, &new.crtc.mode) {
            (Some(a), Some(b)) => !drm_modes::same_timings(a, b),
            (None, None) => false,
            _ => true,
        } || old.crtc.enable != new.crtc.enable;
        let active_changed = old.crtc.active != new.crtc.active;
        let connectors_changed = old.crtc.enable != new.crtc.enable || old.conn.crtc != new.conn.crtc || old.conn.link != new.conn.link;
        if crtc_in && new.crtc.enable != (new.conn.crtc == CRTC) {
            return Err(Errno::EINVAL);
        }
        let needs_modeset = crtc_in && (mode_changed || active_changed || connectors_changed);
        if needs_modeset {
            for (i, p) in new.planes.iter().enumerate() {
                if p.crtc == CRTC || old.planes[i].crtc == CRTC {
                    planes_in[i] = true;
                }
            }
        }
        // `drm_atomic_helper_check_planes`: virtio's plane check.
        for (i, &inn) in planes_in.iter().enumerate() {
            if inn {
                if needs_modeset {
                    new.planes[i].damage = 0;
                }
                virtio_plane_check(&new, i)?;
            }
        }
        if flags & ALLOW_MODESET == 0 && needs_modeset {
            return Err(Errno::EINVAL);
        }
        if flags & TEST != 0 {
            return Ok(0);
        }
        // The event's room in the file.
        if flags & EVENT != 0 {
            let mut f = self.fl();
            if f.event_space < 32 {
                return Err(Errno::ENOMEM);
            }
            f.event_space -= 32;
        }
        // The new state, and the legacy fields a modeset sets.
        st.kms = new;
        if needs_modeset {
            st.dpms = if st.kms.crtc.active { 0 } else { 3 };
        }
        let dropped = st.sweep();
        let now = crate::syscalls::clock_ns(crate::syscalls::system_clock, 1);
        // The fake vblank: the flip is done now.
        if flags & EVENT != 0 {
            let mut e = [0u8; 32];
            put32(&mut e, 0, 2);
            put32(&mut e, 4, 32);
            put64(&mut e, 8, get64(k, 48));
            put32(&mut e, 16, (now / 1_000_000_000) as u32);
            put32(&mut e, 20, ((now % 1_000_000_000) / 1000) as u32);
            put32(&mut e, 24, 0);
            put32(&mut e, 28, CRTC);
            self.events.lock().unwrap_or_else(|e| e.into_inner()).push_back(e);
        }
        let fence = out_fence.map(|ptr| {
            st.fence_seq += 1;
            (ptr, Fence { driver: "virtio_gpu".into(), timeline: format!("CRTC:{CRTC}-crtc-0"), context: st.fence_ctx, seqno: st.fence_seq, timestamp_ns: now })
        });
        drop(st);
        drop(dropped);
        if let Some((ptr, fence)) = fence {
            let fd = cx.fds.insert(SyncFile::new(fence).open(), true)?;
            m.write_u32(ptr, fd as u32)?;
        }
        g.write_frame();
        Ok(0)
    }
}

/// An object's type, by id: the device's own and the user's.
fn object_type(st: &State, id: u32) -> Option<u32> {
    Some(match id {
        PRIMARY | CURSOR => OBJ_PLANE,
        CRTC => OBJ_CRTC,
        CONN => OBJ_CONNECTOR,
        ENC => OBJ_ENCODER,
        1..=36 if prop(id).is_some() => OBJ_PROPERTY,
        _ if st.blobs.contains_key(&id) => OBJ_BLOB,
        _ if st.fbs.contains_key(&id) => OBJ_FB,
        _ => return None,
    })
}

/// A property's value on an object now.
fn value(st: &State, obj: u32, id: u32) -> u64 {
    let k = &st.kms;
    match obj {
        PRIMARY | CURSOR => {
            let p = &k.planes[(obj - PRIMARY) as usize];
            match id {
                P_TYPE => if obj == PRIMARY { 1 } else { 2 },
                P_FB_ID => p.fb as u64,
                P_IN_FENCE => u64::MAX,
                P_CRTC_ID => p.crtc as u64,
                P_CRTC_X => p.crtc_x as i64 as u64,
                P_CRTC_Y => p.crtc_y as i64 as u64,
                P_CRTC_W => p.crtc_w as u64,
                P_CRTC_H => p.crtc_h as u64,
                P_SRC_X => p.src[0] as u64,
                P_SRC_Y => p.src[1] as u64,
                P_SRC_W => p.src[2] as u64,
                P_SRC_H => p.src[3] as u64,
                P_DAMAGE => p.damage as u64,
                P_HOT_X => p.hot_x as i64 as u64,
                P_HOT_Y => p.hot_y as i64 as u64,
                _ => 0,
            }
        }
        CRTC => match id {
            P_ACTIVE => k.crtc.active as u64,
            P_MODE_ID => k.crtc.mode_blob as u64,
            P_VRR => k.crtc.vrr as u64,
            _ => 0,
        },
        CONN => match id {
            P_DPMS => st.dpms,
            P_LINK => k.conn.link,
            P_CRTC_ID => k.conn.crtc as u64,
            _ => 0,
        },
        _ => 0,
    }
}

/// `drm_property_change_valid_get`.
fn change_valid(st: &State, id: u32, v: u64) -> Result<(), Errno> {
    let p = prop(id).ok_or(Errno::EINVAL)?;
    let ok = if p.flags & IMMUTABLE != 0 {
        false
    } else if p.flags & RANGE != 0 {
        p.values[0] <= v && v <= p.values[1]
    } else if p.flags & SIGNED != 0 {
        (p.values[0] as i64) <= v as i64 && v as i64 <= p.values[1] as i64
    } else if p.flags & BLOB != 0 {
        v == 0 || st.blobs.contains_key(&(v as u32)) && v <= u32::MAX as u64
    } else if p.flags & OBJECT != 0 {
        v == 0 || (v <= u32::MAX as u64 && object_type(st, v as u32) == Some(p.values[0] as u32))
    } else if p.flags & ENUM != 0 {
        p.enums.iter().any(|(e, _)| *e == v)
    } else {
        false
    };
    if ok { Ok(()) } else { Err(Errno::EINVAL) }
}

/// `drm_atomic_plane_check`.
fn plane_check(st: &State, p: &PlaneSt, i: usize) -> Result<(), Errno> {
    if (p.crtc != 0) != (p.fb != 0) {
        return Err(Errno::EINVAL);
    }
    if p.crtc == 0 {
        return Ok(());
    }
    let fb = st.fbs.get(&p.fb).ok_or(Errno::EINVAL)?;
    let formats: &[u32] = if i == 0 { &PRIMARY_FORMATS } else { &CURSOR_FORMATS };
    if !formats.contains(&fb.format) {
        return Err(Errno::EINVAL);
    }
    let max = i32::MAX as u64;
    if p.crtc_w as u64 > max || p.crtc_x as i64 > max as i64 - p.crtc_w as i64 || p.crtc_h as u64 > max || p.crtc_y as i64 > max as i64 - p.crtc_h as i64 {
        return Err(Errno::ERANGE);
    }
    let (fw, fh) = ((fb.width as u64) << 16, (fb.height as u64) << 16);
    let [sx, sy, sw, sh] = p.src.map(|x| x as u64);
    if sw > fw || sx > fw - sw || sh > fh || sy > fh - sh {
        return Err(Errno::ENOSPC);
    }
    if p.damage != 0 {
        if let Some(b) = st.blobs.get(&p.damage) {
            for r in b.data.chunks_exact(16) {
                let c = |o: usize| i32::from_le_bytes(r[o..o + 4].try_into().unwrap()) as i64;
                let (x1, y1, x2, y2) = (c(0), c(4), c(8), c(12));
                if x1 >= x2 || y1 >= y2 || x1 < 0 || y1 < 0 || x2 as u64 > fw || y2 as u64 > fh {
                    return Err(Errno::EINVAL);
                }
            }
        }
    }
    Ok(())
}

/// `virtio_gpu_plane_atomic_check`, which is
/// `drm_atomic_helper_check_plane_state` with no scaling, positioning for
/// the cursor only, and a disabled CRTC allowed.
fn virtio_plane_check(k: &Kms, i: usize) -> Result<(), Errno> {
    let p = &k.planes[i];
    if p.fb == 0 {
        return Ok(());
    }
    // `drm_calc_scale` against exactly 1:1.
    let scale = |src: u32, dst: u32| -> Result<(), Errno> {
        if dst == 0 {
            return Ok(());
        }
        let (src, dst) = (src as u64, dst as u64);
        let s = if src > dst << 16 { src.div_ceil(dst) } else { src / dst };
        if s != 0x10000 { Err(Errno::ERANGE) } else { Ok(()) }
    };
    scale(p.src[2], p.crtc_w)?;
    scale(p.src[3], p.crtc_h)?;
    let (hd, vd) = match (&k.crtc.mode, k.crtc.enable && p.crtc == CRTC) {
        (Some(m), true) => (u16::from_le_bytes([m[4], m[5]]) as i64, u16::from_le_bytes([m[14], m[15]]) as i64),
        _ => (0, 0),
    };
    let (x1, y1) = (p.crtc_x as i64, p.crtc_y as i64);
    let (x2, y2) = (x1 + p.crtc_w as i64, y1 + p.crtc_h as i64);
    let (cx1, cy1, cx2, cy2) = (x1.max(0), y1.max(0), x2.min(hd), y2.min(vd));
    let visible = cx2 > cx1 && cy2 > cy1;
    if !visible {
        return Ok(());
    }
    if i == 0 && (cx1, cy1, cx2, cy2) != (0, 0, hd, vd) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// What ADDFB2 needs of a format: planes, bytes a pixel per plane, the
/// chroma subsampling (`drm_fourcc.c`'s table, for the formats there are).
struct FormatInfo {
    planes: usize,
    cpp: [u32; 3],
    hsub: u32,
    vsub: u32,
}

fn format_info(f: u32) -> Option<FormatInfo> {
    let one = |cpp| Some(FormatInfo { planes: 1, cpp: [cpp, 0, 0], hsub: 1, vsub: 1 });
    let fourcc = |s: &[u8; 4]| u32::from_le_bytes(*s);
    match f {
        _ if [b"C1  ", b"C2  ", b"C4  ", b"R1  ", b"R2  ", b"R4  ", b"D1  ", b"D2  ", b"D4  "].iter().any(|s| fourcc(s) == f) => {
            not_here("ADDFB2 of a format smaller than a byte a pixel");
            None
        }
        _ if [b"C8  ", b"R8  ", b"RGB8", b"BGR8", b"D8  "].iter().any(|s| fourcc(s) == f) => one(1),
        _ if [b"R16 ", b"RG88", b"GR88", b"XR12", b"XB12", b"RX12", b"BX12", b"AR12", b"AB12", b"RA12", b"BA12", b"XR15", b"XB15", b"RX15", b"BX15", b"AR15", b"AB15", b"RA15", b"BA15", b"RG16", b"BG16"].iter().any(|s| fourcc(s) == f) => one(2),
        _ if [b"RG24", b"BG24"].iter().any(|s| fourcc(s) == f) => one(3),
        _ if [b"XR24", b"XB24", b"RX24", b"BX24", b"AR24", b"AB24", b"RA24", b"BA24", b"XR30", b"XB30", b"RX30", b"BX30", b"AR30", b"AB30", b"RA30", b"BA30", b"RG32", b"GR32", b"YUYV", b"YVYU", b"UYVY", b"VYUY", b"AYUV", b"XYUV", b"Y410", b"Y210"].iter().any(|s| fourcc(s) == f) => one(4),
        _ if [b"XR48", b"XB48", b"AR48", b"AB48", b"XR4H", b"XB4H", b"AR4H", b"AB4H", b"Y412", b"Y416"].iter().any(|s| fourcc(s) == f) => one(8),
        _ if f == fourcc(b"NV12") || f == fourcc(b"NV21") => Some(FormatInfo { planes: 2, cpp: [1, 2, 0], hsub: 2, vsub: 2 }),
        _ if f == fourcc(b"NV16") || f == fourcc(b"NV61") => Some(FormatInfo { planes: 2, cpp: [1, 2, 0], hsub: 2, vsub: 1 }),
        _ if f == fourcc(b"NV24") || f == fourcc(b"NV42") => Some(FormatInfo { planes: 2, cpp: [1, 2, 0], hsub: 1, vsub: 1 }),
        _ if f == fourcc(b"P010") || f == fourcc(b"P012") || f == fourcc(b"P016") => Some(FormatInfo { planes: 2, cpp: [2, 4, 0], hsub: 2, vsub: 2 }),
        _ if f == fourcc(b"YU12") || f == fourcc(b"YV12") => Some(FormatInfo { planes: 3, cpp: [1, 1, 1], hsub: 2, vsub: 2 }),
        _ if f == fourcc(b"YU16") || f == fourcc(b"YV16") => Some(FormatInfo { planes: 3, cpp: [1, 1, 1], hsub: 2, vsub: 1 }),
        _ if f == fourcc(b"YU24") || f == fourcc(b"YV24") => Some(FormatInfo { planes: 3, cpp: [1, 1, 1], hsub: 1, vsub: 1 }),
        _ => None,
    }
}

impl FileHandle for DrmFile {
    /// A read takes whole events (`drm_read`).
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        let mut q = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if q.is_empty() {
            return Err(Errno::EAGAIN);
        }
        let mut n = 0;
        while let Some(e) = q.front() {
            if n + e.len() > buf.len() {
                break;
            }
            buf[n..n + e.len()].copy_from_slice(e);
            n += e.len();
            q.pop_front();
            self.fl().event_space += 32;
        }
        Ok(n as u64)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        if let Some(node) = &self.node {
            return Ok(node());
        }
        let rdev = crate::vfs::devices::makedev(MAJOR, if self.render { 128 } else { 0 });
        Ok(Metadata { file_type: FileType::CharDevice, size: 0, mode: 0o600, ino: 1, mtime: 0, nlink: 1, rdev, dev: 0, times: Default::default(), owner: None })
    }

    fn as_drm(self: Arc<Self>) -> Option<Arc<DrmFile>> {
        Some(self)
    }

    fn poll_readable(&self) -> bool {
        !self.events.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }

    fn poll_writable(&self) -> bool {
        false
    }

    /// `drm_gem_mmap`: shared only, at an object's exact offset, no longer
    /// than it, by a file that holds a handle to it.
    fn may_map(&self, offset: u64, len: u64, _prot: u32, shared: bool) -> Result<(), Errno> {
        let g = gpu().ok_or(Errno::ENODEV)?;
        let bo = g.bo_at(offset).filter(|b| b.start == offset && len <= b.size).ok_or(Errno::EINVAL)?;
        if !self.fl().handles.values().any(|b| Arc::ptr_eq(b, &bo)) {
            return Err(Errno::EACCES);
        }
        if !shared {
            return Err(Errno::EINVAL);
        }
        let mut p = self.pending_map.lock().unwrap_or_else(|e| e.into_inner());
        let me = std::thread::current().id();
        p.retain(|(t, _)| *t != me);
        p.push((me, bo));
        Ok(())
    }

    /// The mapping holds its object, whatever becomes of the handle.
    fn map_hold(&self, _prot: u32, _shared: bool) -> Result<Option<Arc<dyn std::any::Any + Send + Sync>>, Errno> {
        let me = std::thread::current().id();
        let mut p = self.pending_map.lock().unwrap_or_else(|e| e.into_inner());
        Ok(p.iter().position(|(t, _)| *t == me).map(|i| p.remove(i).1 as Arc<dyn std::any::Any + Send + Sync>))
    }

    fn read_mapped(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        let bo = gpu().and_then(|g| g.bo_at(offset)).ok_or(Errno::EINVAL)?;
        Ok(bo.read(offset - bo.start, buf))
    }

    fn write_mapped(&self, offset: u64, buf: &[u8]) -> SysResult {
        let bo = gpu().and_then(|g| g.bo_at(offset)).ok_or(Errno::EINVAL)?;
        Ok(bo.write(offset - bo.start, buf))
    }

    /// A mapping is of the object at its offset, wherever that is.
    fn mapped_len(&self) -> Option<u64> {
        Some(u64::MAX)
    }

    fn changes(&self) -> u64 {
        gpu().map_or(0, |g| g.changes.load(Relaxed))
    }
}

/// A dma-buf: an exported object.
#[derive(Debug)]
pub struct DmaBuf {
    bo: Arc<Bo>,
    ino: u64,
    name: Mutex<String>,
}

impl DmaBuf {
    /// The `DMA_BUF_SET_NAME` name, which `/proc/self/fdinfo` would say.
    pub fn name(&self) -> String {
        self.name.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl FileHandle for DmaBuf {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::EINVAL)
    }

    /// An inode of the dmabuf filesystem: mode 0600, the object's size.
    /// (Linux's has no type bits in `st_mode`; here it says a regular file.)
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Regular, size: self.bo.size, mode: 0o600, ino: self.ino, mtime: 0, nlink: 1, rdev: 0, dev: 0, times: Default::default(), owner: None })
    }

    fn fs_dev(&self) -> u64 {
        crate::vfs::anon_dev(crate::vfs::DevKey::Kind("dmabuf"))
    }

    fn as_dmabuf(self: Arc<Self>) -> Option<Arc<DmaBuf>> {
        Some(self)
    }

    /// `dma_buf_llseek`: to the end or the start, nowhere else.
    fn seek(&self, offset: i64, whence: u32) -> Option<SysResult> {
        Some(match (offset, whence) {
            (0, 2) => Ok(self.bo.size),
            (0, 0) => Ok(0),
            _ => Err(Errno::EINVAL),
        })
    }

    fn may_map(&self, offset: u64, len: u64, _prot: u32, shared: bool) -> Result<(), Errno> {
        if offset / PAGE + len / PAGE > self.bo.size / PAGE || !shared {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    fn read_mapped(&self, offset: u64, buf: &mut [u8]) -> SysResult {
        Ok(self.bo.read(offset, buf))
    }

    fn write_mapped(&self, offset: u64, buf: &[u8]) -> SysResult {
        Ok(self.bo.write(offset, buf))
    }

    fn changes(&self) -> u64 {
        self.bo.changes.load(Relaxed)
    }

    fn ioctl(&self, m: &mut GuestMem<'_>, request: u64, arg: u64) -> Option<SysResult> {
        const SYNC: u64 = 0x4008_6200;
        const SET_NAME_A: u64 = 0x4004_6201;
        const SET_NAME_B: u64 = 0x4008_6201;
        const EXPORT_SYNC_FILE: u64 = 0xc008_6202;
        const IMPORT_SYNC_FILE: u64 = 0x4008_6203;
        Some(match request & 0xffff_ffff {
            SYNC => m.read_u64(arg).and_then(|f| if f & !7 != 0 || f & 3 == 0 { Err(Errno::EINVAL) } else { Ok(0) }),
            SET_NAME_A | SET_NAME_B => {
                let mut buf = [0u8; 32];
                match m.read_cstr_into(arg, &mut buf) {
                    Ok(Some(n)) => {
                        *self.name.lock().unwrap_or_else(|e| e.into_inner()) = String::from_utf8_lossy(&buf[..n]).into_owned();
                        Ok(0)
                    }
                    Ok(None) => Err(Errno::EINVAL),
                    Err(e) => Err(e),
                }
            }
            EXPORT_SYNC_FILE | IMPORT_SYNC_FILE => {
                not_here("dma-buf sync files");
                Err(Errno::EINVAL)
            }
            _ => Err(Errno::ENOTTY),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_properties_are_where_linux_has_them() {
        assert_eq!(prop(1).unwrap().name, "EDID");
        assert_eq!(prop(32).unwrap().name, "SIZE_HINTS");
        assert!(prop(33).is_none() && prop(34).is_none());
        assert_eq!((prop(35).unwrap().name, prop(35).unwrap().flags), ("HOTSPOT_X", SIGNED));
        assert_eq!(prop(P_FB_ID).unwrap().name, "FB_ID");
        assert_eq!(prop(P_MODE_ID).unwrap().name, "MODE_ID");
        assert_eq!(prop(P_OUT_FENCE).unwrap().name, "OUT_FENCE_PTR");
    }

    #[test]
    fn the_ioctl_table_is_linuxs() {
        assert_eq!(entry(0xbc), Some((0xc038_64bc, MASTER)));
        assert_eq!(entry(0xb2), Some((0xc020_64b2, RENDER)));
        assert!(entry(0x03).is_none() && entry(0x4c).is_none());
        let fourcc = |s: &[u8; 4]| u32::from_le_bytes(*s);
        assert_eq!(fourcc(b"XR24"), PRIMARY_FORMATS[0]);
        assert_eq!(fourcc(b"AB24"), PRIMARY_FORMATS[7]);
    }
}
