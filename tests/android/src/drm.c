// A virtio-gpu DRM device, used as Android's guest-rendering stack uses
// it: minigbm's dumb buffers on the render node, shared as dma-bufs;
// the goldfish composer's atomic mode setting on card0, with an
// out-fence each frame.
//
// - The driver says who it is (VERSION), its capabilities (GET_CAP), and
//   which client capabilities it takes; the render node refuses mode
//   setting (EACCES).
// - card0's first opener is master. The objects: one CRTC, one connector
//   (virtual), one encoder, a primary and a cursor plane, listed by
//   GETRESOURCES and GETPLANERESOURCES as the client's capabilities say;
//   their properties by name, flags and order. A master's GETCONNECTOR
//   with no room for modes probes it: connected, with modes.
// - Dumb buffers: pitch and size, the formats refused; the fake mmap
//   offset; mmap shared only, by a file holding a handle, at the exact
//   offset. PRIME: one dma-buf per object, its fstat, lseek, link and
//   ioctls; imported back as the same object (the prime table's handle),
//   and its bytes the same through both mappings.
// - Framebuffers (ADDFB2's checks), property blobs, and atomic commits:
//   the argument checks, a test of a modeset, the plane checks (1:1 only,
//   covering the CRTC), a commit with an out-fence (a sync file, already
//   signalled, named for the CRTC), a page-flip event, a sync-file merge,
//   and RMFB of the shown framebuffer (the CRTC stays on).
// - VIRTGPU_GETPARAM's answers on a 2D device.
//
// ids are printed relative to one another: a kernel with fbdev emulation
// (Ubuntu's) has used some before the test runs. Its nodes are the test's
// own, by number, in a tmpfs it mounts. Needs root (exit 77 without);
// with no virtio-gpu (no 226:0) it says so and exits 77.
#define _GNU_SOURCE
#include <drm/drm.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_mode.h>
#include <drm/virtgpu_drm.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/dma-buf.h>
#include <linux/sync_file.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

// Newer than the NDK's headers.
#ifndef DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT
#define DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT 6
#endif

// What Linux 7.0 printed (filled in from its run).
static const char expected[] = "";

static char out_buf[16384];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[512];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    fflush(stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static int io(int fd, unsigned long req, void *arg) {
    return ioctl(fd, req, arg) < 0 ? -errno : 0;
}

static char top[64];

static int node(const char *name, int minor) {
    char path[128];
    snprintf(path, sizeof path, "%s/%s", top, name);
    if (mknod(path, S_IFCHR | 0666, makedev(226, minor)) && errno != EEXIST) {
        printf("drm: mknod %s: %d\n", name, errno);
        exit(1);
    }
    return open(path, O_RDWR | O_CLOEXEC);
}

static void props_of(int fd, uint32_t obj, uint32_t type, const char *what, uint32_t base) {
    struct drm_mode_obj_get_properties gp = {.obj_id = obj, .obj_type = type};
    int r = io(fd, DRM_IOCTL_MODE_OBJ_GETPROPERTIES, &gp);
    if (r) {
        SAY("%s properties: %d\n", what, r);
        return;
    }
    uint32_t ids[32];
    uint64_t vals[32];
    gp.props_ptr = (uintptr_t)ids;
    gp.prop_values_ptr = (uintptr_t)vals;
    if (gp.count_props > 32) gp.count_props = 32;
    io(fd, DRM_IOCTL_MODE_OBJ_GETPROPERTIES, &gp);
    SAY("%s properties (%u):", what, gp.count_props);
    for (uint32_t i = 0; i < gp.count_props; i++) {
        struct drm_mode_get_property p = {.prop_id = ids[i]};
        io(fd, DRM_IOCTL_MODE_GETPROPERTY, &p);
        // The standard ones are below the planes; the hotspots after them.
        SAY(" %s/%x%s", p.name, p.flags, ids[i] < base ? "" : "+");
    }
    SAY("\n");
}

static int get_conn(int fd, uint32_t id, struct drm_mode_get_connector *c, struct drm_mode_modeinfo *modes, int max) {
    memset(c, 0, sizeof *c);
    c->connector_id = id;
    int r = io(fd, DRM_IOCTL_MODE_GETCONNECTOR, c);
    if (r || !modes) return r;
    uint32_t enc[4];
    c->count_modes = c->count_modes > (uint32_t)max ? 0 : c->count_modes;
    c->modes_ptr = (uintptr_t)modes;
    c->count_encoders = 4;
    c->encoders_ptr = (uintptr_t)enc;
    c->count_props = 0;
    return io(fd, DRM_IOCTL_MODE_GETCONNECTOR, c);
}

static uint32_t prop_id(int fd, uint32_t obj, uint32_t type, const char *name) {
    struct drm_mode_obj_get_properties gp = {.obj_id = obj, .obj_type = type};
    uint32_t ids[32];
    uint64_t vals[32];
    gp.props_ptr = (uintptr_t)ids;
    gp.prop_values_ptr = (uintptr_t)vals;
    gp.count_props = 32;
    if (io(fd, DRM_IOCTL_MODE_OBJ_GETPROPERTIES, &gp)) return 0;
    for (uint32_t i = 0; i < gp.count_props && i < 32; i++) {
        struct drm_mode_get_property p = {.prop_id = ids[i]};
        io(fd, DRM_IOCTL_MODE_GETPROPERTY, &p);
        if (!strcmp(p.name, name)) return ids[i];
    }
    return 0;
}

// An atomic request being built.
struct req {
    uint32_t objs[8], counts[8], props[32];
    uint64_t values[32];
    int nobj, nprop;
};

static void add(struct req *r, uint32_t obj, uint32_t prop, uint64_t v) {
    if (!r->nobj || r->objs[r->nobj - 1] != obj) {
        r->objs[r->nobj] = obj;
        r->counts[r->nobj++] = 0;
    }
    r->counts[r->nobj - 1]++;
    r->props[r->nprop] = prop;
    r->values[r->nprop++] = v;
}

static int commit(int fd, struct req *r, uint32_t flags) {
    struct drm_mode_atomic a = {
        .flags = flags,
        .count_objs = r->nobj,
        .objs_ptr = (uintptr_t)r->objs,
        .count_props_ptr = (uintptr_t)r->counts,
        .props_ptr = (uintptr_t)r->props,
        .prop_values_ptr = (uintptr_t)r->values,
        .user_data = 0x1234,
    };
    return io(fd, DRM_IOCTL_MODE_ATOMIC, &a);
}

int main(void) {
    if (geteuid() != 0) {
        printf("drm: needs root\n");
        return 77;
    }
    strcpy(top, "/tmp/drm-XXXXXX");
    if (!mkdtemp(top) || mount("tmpfs", top, "tmpfs", 0, NULL)) {
        printf("drm: a tmpfs: %d\n", errno);
        return 1;
    }
    int card = node("card0", 0);
    if (card < 0) {
        printf("drm: no virtio-gpu (%d)\n", errno);
        umount(top);
        return 77;
    }
    int render = node("renderD128", 128);

    // Who it is.
    char name[32] = {0}, date[32] = {0}, desc[32] = {0};
    struct drm_version v = {.name_len = 4, .name = name, .date_len = 31, .date = date, .desc_len = 31, .desc = desc};
    SAY("version: %d, %d.%d.%d, name %s (%zu) date %s desc %s\n", io(render, DRM_IOCTL_VERSION, &v), v.version_major, v.version_minor, v.version_patchlevel, name, v.name_len, date, desc);
    SAY("caps:");
    for (uint64_t c = 0; c <= 0x16; c++) {
        struct drm_get_cap gc = {.capability = c, .value = 99};
        int r = io(card, DRM_IOCTL_GET_CAP, &gc);
        SAY(" %llx=%s%lld", (unsigned long long)c, r ? "e" : "", r ? (long long)r : (long long)gc.value);
    }
    SAY("\n");

    // The render node takes no mode setting.
    struct drm_mode_card_res res = {0};
    struct drm_set_client_cap cc = {.capability = DRM_CLIENT_CAP_UNIVERSAL_PLANES, .value = 1};
    SAY("render node: resources %d, client cap %d\n", io(render, DRM_IOCTL_MODE_GETRESOURCES, &res), io(render, DRM_IOCTL_SET_CLIENT_CAP, &cc));

    // The objects.
    uint32_t crtcs[4], conns[4], encs[4], fbs[8];
    res = (struct drm_mode_card_res){.crtc_id_ptr = (uintptr_t)crtcs, .count_crtcs = 4, .connector_id_ptr = (uintptr_t)conns, .count_connectors = 4, .encoder_id_ptr = (uintptr_t)encs, .count_encoders = 4, .fb_id_ptr = (uintptr_t)fbs, .count_fbs = 8};
    int r = io(card, DRM_IOCTL_MODE_GETRESOURCES, &res);
    uint32_t crtc = crtcs[0], conn = conns[0], enc = encs[0];
    SAY("resources: %d, %u crtcs %u connectors %u encoders %u fbs, %ux%u to %ux%u; connector is the crtc + %d, encoder + %d\n", r, res.count_crtcs, res.count_connectors, res.count_encoders, res.count_fbs, res.min_width, res.min_height, res.max_width, res.max_height, (int)(conn - crtc), (int)(enc - crtc));
    uint32_t planes[4];
    struct drm_mode_get_plane_res pr = {.plane_id_ptr = (uintptr_t)planes, .count_planes = 4};
    io(card, DRM_IOCTL_MODE_GETPLANERESOURCES, &pr);
    SAY("planes, no caps: %u\n", pr.count_planes);
    cc.value = 2;
    SAY("universal planes 2: %d\n", io(card, DRM_IOCTL_SET_CLIENT_CAP, &cc));
    cc.value = 1;
    io(card, DRM_IOCTL_SET_CLIENT_CAP, &cc);
    pr.count_planes = 4;
    io(card, DRM_IOCTL_MODE_GETPLANERESOURCES, &pr);
    uint32_t primary = planes[0], cursor = planes[1];
    SAY("planes, universal: %u, the crtc - %d and - %d\n", pr.count_planes, (int)(crtc - primary), (int)(crtc - cursor));
    struct drm_set_client_cap hot = {.capability = DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT, .value = 1};
    SAY("hotspot before atomic: %d\n", io(card, DRM_IOCTL_SET_CLIENT_CAP, &hot));
    cc.capability = DRM_CLIENT_CAP_ATOMIC;
    cc.value = 3;
    SAY("atomic 3: %d\n", io(card, DRM_IOCTL_SET_CLIENT_CAP, &cc));
    cc.value = 1;
    SAY("atomic 1: %d\n", io(card, DRM_IOCTL_SET_CLIENT_CAP, &cc));
    pr.count_planes = 4;
    io(card, DRM_IOCTL_MODE_GETPLANERESOURCES, &pr);
    SAY("planes, atomic: %u\n", pr.count_planes);
    SAY("hotspot: %d\n", io(card, DRM_IOCTL_SET_CLIENT_CAP, &hot));
    pr.count_planes = 4;
    io(card, DRM_IOCTL_MODE_GETPLANERESOURCES, &pr);
    SAY("planes, atomic and hotspot: %u\n", pr.count_planes);
    uint32_t fmts[16];
    struct drm_mode_get_plane gpl = {.plane_id = primary, .format_type_ptr = (uintptr_t)fmts, .count_format_types = 16};
    io(card, DRM_IOCTL_MODE_GETPLANE, &gpl);
    SAY("primary: crtcs %x, %u formats:", gpl.possible_crtcs, gpl.count_format_types);
    for (uint32_t i = 0; i < gpl.count_format_types; i++) SAY(" %.4s", (char *)&fmts[i]);
    gpl = (struct drm_mode_get_plane){.plane_id = cursor, .format_type_ptr = (uintptr_t)fmts, .count_format_types = 16};
    io(card, DRM_IOCTL_MODE_GETPLANE, &gpl);
    SAY("; cursor: %u, %.4s\n", gpl.count_format_types, (char *)&fmts[0]);
    props_of(card, primary, DRM_MODE_OBJECT_PLANE, "primary", primary);
    props_of(card, cursor, DRM_MODE_OBJECT_PLANE, "cursor", primary);
    props_of(card, crtc, DRM_MODE_OBJECT_CRTC, "crtc", primary);
    props_of(card, conn, DRM_MODE_OBJECT_CONNECTOR, "connector", primary);
    props_of(card, enc, DRM_MODE_OBJECT_ENCODER, "encoder", primary);
    props_of(card, conn, DRM_MODE_OBJECT_CRTC, "connector as a crtc", primary);
    struct drm_mode_property_enum en[8];
    struct drm_mode_get_property gp = {.prop_id = prop_id(card, conn, DRM_MODE_OBJECT_CONNECTOR, "DPMS"), .enum_blob_ptr = (uintptr_t)en, .count_enum_blobs = 8};
    io(card, DRM_IOCTL_MODE_GETPROPERTY, &gp);
    SAY("DPMS: %u values, %u enums: %s %s %s %s\n", gp.count_values, gp.count_enum_blobs, en[0].name, en[1].name, en[2].name, en[3].name);

    // The connector, probed by its master.
    static struct drm_mode_modeinfo modes[64];
    struct drm_mode_get_connector c;
    r = get_conn(card, conn, &c, modes, 64);
    SAY("connector: %d, type %u/%u, %s, %u encoders, mm %ux%u, %d modes\n", r, c.connector_type, c.connector_type_id, c.connection == 1 ? "connected" : "not connected", c.count_encoders, c.mm_width, c.mm_height, c.count_modes > 0);
    int m640 = -1;
    for (uint32_t i = 0; i < c.count_modes && i < 64; i++)
        if (modes[i].hdisplay == 640 && modes[i].vdisplay == 480) m640 = i;
    SAY("first mode preferred %d; 640x480: clock %u, %u %u %u %u / %u %u %u %u, %u Hz, flags %x type %x\n", (modes[0].type & DRM_MODE_TYPE_PREFERRED) != 0, modes[m640].clock, modes[m640].hdisplay, modes[m640].hsync_start, modes[m640].hsync_end, modes[m640].htotal, modes[m640].vdisplay, modes[m640].vsync_start, modes[m640].vsync_end, modes[m640].vtotal, modes[m640].vrefresh, modes[m640].flags, modes[m640].type);
    struct drm_mode_get_encoder ge = {.encoder_id = enc};
    SAY("encoder: %d, type %u, crtcs %x clones %x\n", io(card, DRM_IOCTL_MODE_GETENCODER, &ge), ge.encoder_type, ge.possible_crtcs, ge.possible_clones);

    // Dumb buffers.
    struct drm_mode_create_dumb d = {.width = 640, .height = 480, .bpp = 16};
    SAY("dumb 16 bpp: %d (handle %u pitch %u size %llu)\n", io(render, DRM_IOCTL_MODE_CREATE_DUMB, &d), d.handle, d.pitch, (unsigned long long)d.size);
    d = (struct drm_mode_create_dumb){.width = 0, .height = 480, .bpp = 32};
    SAY("dumb width 0: %d\n", io(render, DRM_IOCTL_MODE_CREATE_DUMB, &d));
    d = (struct drm_mode_create_dumb){.width = 641, .height = 3, .bpp = 32, .flags = 0x55};
    SAY("dumb 641x3: %d, pitch %u size %llu\n", io(render, DRM_IOCTL_MODE_CREATE_DUMB, &d), d.pitch, (unsigned long long)d.size);
    struct drm_gem_close gc = {.handle = d.handle};
    io(render, DRM_IOCTL_GEM_CLOSE, &gc);
    SAY("closed again: %d\n", io(render, DRM_IOCTL_GEM_CLOSE, &gc));
    d = (struct drm_mode_create_dumb){.width = 640, .height = 480, .bpp = 32};
    SAY("dumb 640x480: %d, handle %u pitch %u size %llu\n", io(render, DRM_IOCTL_MODE_CREATE_DUMB, &d), d.handle, d.pitch, (unsigned long long)d.size);
    struct drm_mode_map_dumb md = {.handle = d.handle};
    r = io(render, DRM_IOCTL_MODE_MAP_DUMB, &md);
    SAY("map: %d, offset page aligned %d, from 4 GiB %d\n", r, md.offset % 4096 == 0, md.offset >= 0x100000000ull);
    struct drm_mode_map_dumb bad = {.handle = 99};
    SAY("map of no handle: %d\n", io(render, DRM_IOCTL_MODE_MAP_DUMB, &bad));
    void *p = mmap(NULL, d.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, render, md.offset);
    SAY("private mapping: %d\n", p == MAP_FAILED ? -errno : 0);
    p = mmap(NULL, d.size, PROT_READ | PROT_WRITE, MAP_SHARED, render, md.offset + 4096);
    SAY("mapping inside: %d\n", p == MAP_FAILED ? -errno : 0);
    p = mmap(NULL, d.size, PROT_READ | PROT_WRITE, MAP_SHARED, card, md.offset);
    SAY("mapping by a file with no handle: %d\n", p == MAP_FAILED ? -errno : 0);
    uint32_t *px = mmap(NULL, d.size, PROT_READ | PROT_WRITE, MAP_SHARED, render, md.offset);
    SAY("mapping: %d\n", px == MAP_FAILED ? -errno : 0);
    for (int i = 0; i < 640 * 480; i++) px[i] = 0xff000000u | (uint32_t)i;

    // PRIME.
    struct drm_prime_handle ph = {.handle = d.handle, .flags = 4};
    SAY("export, flag 4: %d\n", io(render, DRM_IOCTL_PRIME_HANDLE_TO_FD, &ph));
    ph = (struct drm_prime_handle){.handle = d.handle, .flags = DRM_CLOEXEC | DRM_RDWR};
    r = io(render, DRM_IOCTL_PRIME_HANDLE_TO_FD, &ph);
    int buf = ph.fd;
    struct drm_prime_handle ph2 = {.handle = d.handle, .flags = DRM_CLOEXEC};
    io(render, DRM_IOCTL_PRIME_HANDLE_TO_FD, &ph2);
    struct stat s1, s2;
    fstat(buf, &s1);
    fstat(ph2.fd, &s2);
    char link[64] = {0}, lp[64];
    snprintf(lp, sizeof lp, "/proc/self/fd/%d", buf);
    readlink(lp, link, sizeof link - 1);
    SAY("export: %d, size %lld, perms %o, same inode again %d, link %s, cloexec %d, flags %o\n", r, (long long)s1.st_size, s1.st_mode & 0777, s1.st_ino == s2.st_ino, link, (fcntl(buf, F_GETFD) & FD_CLOEXEC) != 0, fcntl(ph2.fd, F_GETFL) & O_ACCMODE);
    close(ph2.fd);
    SAY("dma-buf lseek end %lld, set 0 %lld, cur %lld; read %zd (%d)\n", (long long)lseek(buf, 0, SEEK_END), (long long)lseek(buf, 0, SEEK_SET), (long long)lseek(buf, 0, SEEK_CUR), read(buf, lp, 4), errno);
    struct dma_buf_sync sy = {.flags = DMA_BUF_SYNC_START};
    SAY("sync, no direction: %d\n", io(buf, DMA_BUF_IOCTL_SYNC, &sy));
    sy.flags = 8 | DMA_BUF_SYNC_RW;
    SAY("sync, flag 8: %d\n", io(buf, DMA_BUF_IOCTL_SYNC, &sy));
    sy.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE;
    SAY("sync end: %d; set name %d, too long %d; other ioctl %d\n", io(buf, DMA_BUF_IOCTL_SYNC, &sy), ioctl(buf, DMA_BUF_SET_NAME_B, "frame") < 0 ? -errno : 0, ioctl(buf, DMA_BUF_SET_NAME_B, "0123456789012345678901234567890123") < 0 ? -errno : 0, io(buf, _IO('b', 9), NULL));
    uint32_t *view = mmap(NULL, d.size, PROT_READ, MAP_SHARED, buf, 0);
    sy.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ;
    io(buf, DMA_BUF_IOCTL_SYNC, &sy);
    SAY("dma-buf mapping: %d, same pixels %d %d; private %d\n", view == MAP_FAILED ? -errno : 0, view != MAP_FAILED && view[0] == px[0], view != MAP_FAILED && view[640 * 480 - 1] == px[640 * 480 - 1], mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, buf, 0) == MAP_FAILED ? -errno : 0);
    struct drm_prime_handle imp = {.fd = buf};
    r = io(card, DRM_IOCTL_PRIME_FD_TO_HANDLE, &imp);
    uint32_t h = imp.handle;
    imp.handle = 0;
    io(card, DRM_IOCTL_PRIME_FD_TO_HANDLE, &imp);
    struct drm_prime_handle back = {.fd = buf};
    io(render, DRM_IOCTL_PRIME_FD_TO_HANDLE, &back);
    struct drm_prime_handle notbuf = {.fd = card};
    struct drm_prime_handle nofd = {.fd = 999};
    SAY("import: %d, handle %u, again %u; back where it came from %u; not a dma-buf %d; no descriptor %d\n", r, h, imp.handle, back.handle, io(card, DRM_IOCTL_PRIME_FD_TO_HANDLE, &notbuf), io(card, DRM_IOCTL_PRIME_FD_TO_HANDLE, &nofd));
    struct drm_mode_map_dumb md2 = {.handle = h};
    io(card, DRM_IOCTL_MODE_MAP_DUMB, &md2);
    SAY("imported offset is the object's %d\n", md2.offset == md.offset);
    struct drm_virtgpu_resource_info ri = {.bo_handle = h};
    r = io(card, DRM_IOCTL_VIRTGPU_RESOURCE_INFO, &ri);
    SAY("resource info: %d, size %u, resource above 1 %d\n", r, ri.size, ri.res_handle > 1);

    // Framebuffers.
    struct drm_mode_fb_cmd2 fb = {.width = 640, .height = 480, .pixel_format = DRM_FORMAT_XRGB8888, .handles = {h}, .pitches = {2560}};
    SAY("addfb2 on the render node: %d\n", io(render, DRM_IOCTL_MODE_ADDFB2, &fb));
    fb.pitches[0] = 2556;
    SAY("addfb2, pitch short: %d\n", io(card, DRM_IOCTL_MODE_ADDFB2, &fb));
    fb.pitches[0] = 2560;
    fb.width = 16;
    SAY("addfb2, 16 wide: %d\n", io(card, DRM_IOCTL_MODE_ADDFB2, &fb));
    fb.width = 640;
    fb.handles[0] = 77;
    SAY("addfb2, no such handle: %d\n", io(card, DRM_IOCTL_MODE_ADDFB2, &fb));
    fb.handles[0] = h;
    fb.pixel_format = DRM_FORMAT_RGB565;
    fb.pitches[0] = 1280;
    r = io(card, DRM_IOCTL_MODE_ADDFB2, &fb);
    uint32_t fb565 = fb.fb_id;
    SAY("addfb2, RGB565 no plane takes: %d\n", r);
    fb.pixel_format = DRM_FORMAT_XRGB8888;
    fb.pitches[0] = 2560;
    r = io(card, DRM_IOCTL_MODE_ADDFB2, &fb);
    uint32_t fbid = fb.fb_id;
    SAY("addfb2: %d, the newer above the older %d\n", r, fbid > fb565);
    res = (struct drm_mode_card_res){.fb_id_ptr = (uintptr_t)fbs, .count_fbs = 8};
    io(card, DRM_IOCTL_MODE_GETRESOURCES, &res);
    SAY("this file's fbs: %u, newest first %d\n", res.count_fbs, fbs[0] == fbid && fbs[1] == fb565);

    // A mode blob.
    struct drm_mode_create_blob cb = {.data = (uintptr_t)&modes[m640], .length = sizeof modes[0]};
    r = io(card, DRM_IOCTL_MODE_CREATEPROPBLOB, &cb);
    uint32_t blob = cb.blob_id;
    struct drm_mode_get_blob gb = {.blob_id = blob};
    io(card, DRM_IOCTL_MODE_GETPROPBLOB, &gb);
    struct drm_mode_create_blob empty = {.data = (uintptr_t)modes, .length = 0};
    SAY("blob: %d, length %u, empty %d\n", r, gb.length, io(card, DRM_IOCTL_MODE_CREATEPROPBLOB, &empty));

    // Atomic.
    uint32_t P_CRTC_ID = prop_id(card, primary, DRM_MODE_OBJECT_PLANE, "CRTC_ID"), P_FB = prop_id(card, primary, DRM_MODE_OBJECT_PLANE, "FB_ID");
    uint32_t P_SX = prop_id(card, primary, DRM_MODE_OBJECT_PLANE, "SRC_X"), P_SY = P_SX + 1, P_SW = P_SX + 2, P_SH = P_SX + 3;
    uint32_t P_CX = prop_id(card, primary, DRM_MODE_OBJECT_PLANE, "CRTC_X"), P_CY = P_CX + 1, P_CW = P_CX + 2, P_CH = P_CX + 3;
    uint32_t P_ACTIVE = prop_id(card, crtc, DRM_MODE_OBJECT_CRTC, "ACTIVE"), P_MODE = prop_id(card, crtc, DRM_MODE_OBJECT_CRTC, "MODE_ID"), P_OUT = prop_id(card, crtc, DRM_MODE_OBJECT_CRTC, "OUT_FENCE_PTR");
    uint32_t P_CONN_CRTC = prop_id(card, conn, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID"), P_DPMS = prop_id(card, conn, DRM_MODE_OBJECT_CONNECTOR, "DPMS");
    struct req q = {0};
    SAY("atomic: flag 8 %d, ", commit(card, &q, 8));
    SAY("test with an event %d, ", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_PAGE_FLIP_EVENT));
    add(&q, enc, P_DPMS, 0);
    SAY("an encoder %d, ", commit(card, &q, 0));
    q = (struct req){0};
    add(&q, crtc, P_DPMS, 0);
    SAY("a property not its own %d, ", commit(card, &q, 0));
    q = (struct req){0};
    add(&q, conn, P_DPMS, 0);
    SAY("DPMS %d\n", commit(card, &q, 0));
    int other = node("card0", 0);
    q = (struct req){0};
    SAY("not the master: %d\n", commit(other, &q, 0));
    struct req full = {0};
    add(&full, conn, P_CONN_CRTC, crtc);
    add(&full, crtc, P_ACTIVE, 1);
    add(&full, crtc, P_MODE, blob);
    add(&full, primary, P_FB, fbid);
    add(&full, primary, P_CRTC_ID, crtc);
    add(&full, primary, P_SX, 0);
    add(&full, primary, P_SY, 0);
    add(&full, primary, P_SW, 640 << 16);
    add(&full, primary, P_SH, 480 << 16);
    add(&full, primary, P_CX, 0);
    add(&full, primary, P_CY, 0);
    add(&full, primary, P_CW, 640);
    add(&full, primary, P_CH, 480);
    SAY("a modeset without leave: %d; test: %d\n", commit(card, &full, DRM_MODE_ATOMIC_TEST_ONLY), commit(card, &full, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    q = full;
    q.values[q.nprop - 2] = 320;
    SAY("scaled: %d, ", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    q = full;
    q.values[q.nprop - 4] = 10;
    SAY("not covering: %d, ", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    q = full;
    q.values[3] = fb565;
    SAY("a format it does not take: %d, ", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    q = full;
    q.values[2] = 0;
    SAY("active with no mode: %d, ", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    q = full;
    q.values[0] = 0;
    SAY("a mode with no connector: %d, ", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    q = full;
    q.values[3] = 0;
    SAY("a crtc with no fb: %d, ", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    q = full;
    q.values[2] = fbid;
    SAY("a blob that is not: %d\n", commit(card, &q, DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET));
    int fence = 77;
    q = full;
    add(&q, crtc, P_OUT, (uintptr_t)&fence);
    r = commit(card, &q, DRM_MODE_ATOMIC_ALLOW_MODESET);
    struct pollfd pf = {.fd = fence, .events = POLLIN | POLLOUT};
    int pr2 = poll(&pf, 1, 0);
    struct sync_fence_info fi = {0};
    struct sync_file_info sfi = {.num_fences = 1, .sync_fence_info = (uintptr_t)&fi};
    int ir = io(fence, SYNC_IOC_FILE_INFO, &sfi);
    char tl[32];
    snprintf(tl, sizeof tl, "CRTC:%u-crtc-0", crtc);
    SAY("commit: %d, fence %d, poll %d %x, info %d, status %d, %u fences, driver %s, timeline is the crtc's %d, cloexec %d\n", r, fence >= 0, pr2, pf.revents, ir, sfi.status, sfi.num_fences, fi.driver_name, !strcmp(fi.obj_name, tl), (fcntl(fence, F_GETFD) & FD_CLOEXEC) != 0);
    struct sync_merge_data mg = {.name = "both", .fd2 = fence};
    r = io(fence, SYNC_IOC_MERGE, &mg);
    struct sync_file_info mi = {.num_fences = 1, .sync_fence_info = (uintptr_t)&fi};
    io(mg.fence, SYNC_IOC_FILE_INFO, &mi);
    struct sync_merge_data mg2 = {.name = "x", .fd2 = card};
    SAY("merge: %d, name %s, driver %s, timeline %s; with a non-fence %d\n", r, mi.name, fi.driver_name, fi.obj_name, io(fence, SYNC_IOC_MERGE, &mg2));
    struct drm_mode_crtc gcr = {.crtc_id = crtc};
    io(card, DRM_IOCTL_MODE_GETCRTC, &gcr);
    ge = (struct drm_mode_get_encoder){.encoder_id = enc};
    io(card, DRM_IOCTL_MODE_GETENCODER, &ge);
    get_conn(card, conn, &c, NULL, 0);
    SAY("after: crtc mode valid %u %ux%u fb is ours %d; encoder on the crtc %d; connector's encoder %d\n", gcr.mode_valid, gcr.mode.hdisplay, gcr.mode.vdisplay, gcr.fb_id == fbid, ge.crtc_id == crtc, c.encoder_id == enc);
    q = (struct req){0};
    add(&q, primary, P_FB, fbid);
    r = commit(card, &q, DRM_MODE_PAGE_FLIP_EVENT);
    struct drm_event_vblank ev = {0};
    ssize_t n = read(card, &ev, sizeof ev);
    SAY("flip: %d, read %zd, type %u length %u data %llx sequence %u crtc is ours %d\n", r, n, ev.base.type, ev.base.length, (unsigned long long)ev.user_data, ev.sequence, ev.crtc_id == crtc);
    fcntl(card, F_SETFL, O_NONBLOCK);
    n = read(card, &ev, sizeof ev);
    SAY("nothing more: %zd %d\n", n, errno);
    struct drm_mode_destroy_blob db = {.blob_id = blob};
    SAY("destroy the mode in use: %d, by another file %d\n", io(card, DRM_IOCTL_MODE_DESTROYPROPBLOB, &db), io(other, DRM_IOCTL_MODE_DESTROYPROPBLOB, &db));
    uint32_t rm = fbid;
    SAY("rmfb by another file: %d; ", io(other, DRM_IOCTL_MODE_RMFB, &rm));
    r = io(card, DRM_IOCTL_MODE_RMFB, &rm);
    gcr = (struct drm_mode_crtc){.crtc_id = crtc};
    io(card, DRM_IOCTL_MODE_GETCRTC, &gcr);
    SAY("rmfb: %d, crtc still on %u, fb %u; again %d\n", r, gcr.mode_valid, gcr.fb_id, io(card, DRM_IOCTL_MODE_RMFB, &rm));

    // virtio's own.
    SAY("getparam:");
    for (uint64_t i = 0; i <= 9; i++) {
        int val = -5;
        struct drm_virtgpu_getparam g = {.param = i, .value = (uintptr_t)&val};
        int rr = io(render, DRM_IOCTL_VIRTGPU_GETPARAM, &g);
        SAY(" %llu=%s%d", (unsigned long long)i, rr ? "e" : "", rr ? rr : val);
    }
    struct drm_virtgpu_get_caps gcaps = {0};
    struct drm_virtgpu_3d_transfer_from_host tf = {0};
    SAY("; get caps %d, transfer from %d, unknown driver ioctl %d, not 'd' %d\n", io(render, DRM_IOCTL_VIRTGPU_GET_CAPS, &gcaps), io(render, DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST, &tf), io(render, DRM_IOWR(0x4c, struct drm_virtgpu_getparam), &gcaps), io(render, _IOWR('e', 1, int), &gcaps));

    close(other);
    close(card);
    close(render);
    umount(top);
    rmdir(top);
    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("drm: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "drm ok\n" : "drm done\n");
    return 0;
}
