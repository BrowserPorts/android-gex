// The device-mapper: block devices made of pieces of other block devices,
// through /dev/device-mapper (10:236). Android's apexd makes one for
// every APEX, and fs_mgr the system's partitions.
//
// - DM_VERSION answers the interface's version (4.x).
// - DM_DEV_CREATE makes a device by name (and uuid): a number, with no
//   disk behind it (its node is ENXIO, sysfs has nothing) until it is
//   given a table. A name in use is EBUSY; a name with a slash in it, or
//   none, EINVAL.
// - DM_DEV_STATUS finds it by name, by uuid or by number, one of them
//   only (ENXIO for none and for a number with another, EINVAL for a
//   name with a uuid), with
//   its number and what tables it has.
// - DM_LIST_DEVICES lists it.
// - DM_TABLE_LOAD gives it a table that waits: targets end to end from
//   sector 0, each a type and its words. `linear` is a run of another
//   device from an offset, `zero` reads zeros, `error` fails. A type
//   there is not, or a gap, is EINVAL.
// - DM_DEV_SUSPEND with no flag makes the waiting table the device's:
//   it is then as long as its table, and reads what its targets say.
//   With the suspend flag the device is suspended, and says so.
// - DM_TABLE_STATUS reads the table back; DM_TABLE_DEPS the devices it
//   is made of.
// - sysfs has it as block/dm-<n>, with dm/name, dm/uuid, dm/suspended.
// - DM_DEV_REMOVE takes it away: EBUSY while it is open, ENXIO when it
//   is not there.
//
// The nodes are the test's own, in a tmpfs it mounts; the device under
// the table is a loop device over a file there.
//
// Needs root; without it the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define SECTORS 2048

static char top[64], sys[64], name[64], uuid[64];
static int ctl;

static void die(const char *what, long a, long b) {
    printf("dmctl: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *in(const char *dir, const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", dir, path);
    return out;
}

// A request: the header, then room for what goes with it and comes back.
union request {
    struct dm_ioctl io;
    char bytes[16384];
};

static void start(union request *r, const char *dev_name, unsigned flags) {
    memset(r, 0, sizeof *r);
    r->io.version[0] = 4;
    r->io.data_size = sizeof *r;
    r->io.data_start = sizeof r->io;
    r->io.flags = flags;
    if (dev_name) strcpy(r->io.name, dev_name);
}

// One call: 0, or the errno.
static int call(unsigned long cmd, union request *r) {
    return ioctl(ctl, cmd, r) ? errno : 0;
}

// Add a target to a table being built in `r`: its start and length in
// sectors, its type and its words.
static void target(union request *r, uint64_t from, uint64_t length, const char *type, const char *words) {
    char *at = r->bytes + r->io.data_start;
    for (unsigned i = 0; i < r->io.target_count; i++) at += ((struct dm_target_spec *)at)->next;
    struct dm_target_spec *spec = (struct dm_target_spec *)at;
    memset(spec, 0, sizeof *spec);
    spec->sector_start = from;
    spec->length = length;
    strcpy(spec->target_type, type);
    strcpy(at + sizeof *spec, words);
    spec->next = (sizeof *spec + strlen(words) + 1 + 7) & ~7u;
    r->io.target_count++;
}

static uint64_t size_of(int fd) {
    uint64_t size = 99;
    if (ioctl(fd, BLKGETSIZE64, &size)) die("BLKGETSIZE64", errno, 0);
    return size;
}

static unsigned char byte_at(long at) {
    return (unsigned char)(at * 11 + at / 509);
}

static void reads(const char *path, const char *want) {
    char text[256] = {0};
    int fd = open(in(sys, path), O_RDONLY);
    if (fd < 0) die(path, errno, 0);
    if (read(fd, text, sizeof text - 1) < 0 || strcmp(text, want)) {
        printf("dmctl: %s reads '%s', not '%s'\n", path, text, want);
        exit(1);
    }
    close(fd);
}

int main(void) {
    if (geteuid() != 0) {
        printf("dmctl: needs root\n");
        return 77;
    }
    strcpy(top, "/tmp/dmctl-XXXXXX");
    strcpy(sys, "/tmp/dmctl-sys-XXXXXX");
    if (!mkdtemp(top) || mount("tmpfs", top, "tmpfs", 0, NULL)) die("a tmpfs", errno, 0);
    if (!mkdtemp(sys) || mount("sysfs", sys, "sysfs", 0, NULL)) die("sysfs", errno, 0);
    snprintf(name, sizeof name, "gex-dm-test-%d", getpid());
    snprintf(uuid, sizeof uuid, "gex-dm-uuid-%d", getpid());

    // A loop device over a file, for the tables to be made of.
    if (mknod(in(top, "loop-control"), S_IFCHR | 0600, makedev(10, 237))) die("mknod", errno, 0);
    int lctl = open(in(top, "loop-control"), O_RDWR);
    int file = open(in(top, "backing"), O_RDWR | O_CREAT, 0600);
    static unsigned char data[SECTORS * 512];
    for (long i = 0; i < (long)sizeof data; i++) data[i] = byte_at(i);
    if (lctl < 0 || file < 0 || write(file, data, sizeof data) != (ssize_t)sizeof data) die("the file", errno, 0);
    int loop = -1, number = -1;
    for (int tries = 0; tries < 20 && loop < 0; tries++) {
        number = ioctl(lctl, LOOP_CTL_GET_FREE);
        unlink(in(top, "loop"));
        if (number < 0 || mknod(in(top, "loop"), S_IFBLK | 0600, makedev(7, number))) die("a loop device", errno, 0);
        loop = open(in(top, "loop"), O_RDWR);
        struct loop_config config;
        memset(&config, 0, sizeof config);
        config.fd = file;
        if (loop >= 0 && ioctl(loop, LOOP_CONFIGURE, &config)) {
            if (errno != EBUSY) die("LOOP_CONFIGURE", errno, 0);
            close(loop);
            loop = -1;
        }
    }
    if (loop < 0) die("no loop device to be had", 0, 0);

    // The control.
    if (mknod(in(top, "control"), S_IFCHR | 0600, makedev(10, 236))) die("mknod of the control", errno, 0);
    ctl = open(in(top, "control"), O_RDWR);
    if (ctl < 0) die("open of the control", errno, 0);
    union request r;
    start(&r, NULL, 0);
    if (call(DM_VERSION, &r) || r.io.version[0] != 4 || r.io.version[1] < 1) die("DM_VERSION", errno, r.io.version[0]);
    // An interface this is not: a major version it has not.
    start(&r, NULL, 0);
    r.io.version[0] = 5;
    if (call(DM_VERSION, &r) != EINVAL) die("a version there is not", errno, 0);

    // A device.
    start(&r, name, 0);
    strcpy(r.io.uuid, uuid);
    if (call(DM_DEV_CREATE, &r)) die("DM_DEV_CREATE", errno, 0);
    uint64_t dev = r.io.dev;
    if (major(dev) == 0 || r.io.target_count != 0 || r.io.open_count != 0 || (r.io.flags & (DM_ACTIVE_PRESENT_FLAG | DM_INACTIVE_PRESENT_FLAG | DM_SUSPEND_FLAG))) die("a new device", r.io.flags, r.io.open_count);
    start(&r, name, 0);
    if (call(DM_DEV_CREATE, &r) != EBUSY) die("a name in use", errno, 0);
    start(&r, "with/slash", 0);
    if (call(DM_DEV_CREATE, &r) != EINVAL) die("a name with a slash", errno, 0);
    start(&r, "", 0);
    if (call(DM_DEV_CREATE, &r) != EINVAL) die("no name", errno, 0);
    // Found by name and by uuid.
    start(&r, name, 0);
    if (call(DM_DEV_STATUS, &r) || r.io.dev != dev || strcmp(r.io.uuid, uuid)) die("DM_DEV_STATUS by name", errno, r.io.dev);
    start(&r, NULL, 0);
    strcpy(r.io.uuid, uuid);
    if (call(DM_DEV_STATUS, &r) || r.io.dev != dev || strcmp(r.io.name, name)) die("DM_DEV_STATUS by uuid", errno, r.io.dev);
    // And by its number (ueventd asks so, of each device it hears of),
    // which answers with both; by one of the three only.
    start(&r, NULL, 0);
    r.io.dev = dev;
    if (call(DM_DEV_STATUS, &r) || r.io.dev != dev || strcmp(r.io.name, name) || strcmp(r.io.uuid, uuid)) die("DM_DEV_STATUS by number", errno, r.io.dev);
    start(&r, name, 0);
    r.io.dev = dev;
    if (call(DM_DEV_STATUS, &r) != ENXIO) die("DM_DEV_STATUS by name and number", errno, 0);
    start(&r, name, 0);
    strcpy(r.io.uuid, uuid);
    if (call(DM_DEV_STATUS, &r) != EINVAL) die("DM_DEV_STATUS by name and uuid", errno, 0);
    start(&r, NULL, 0);
    strcpy(r.io.uuid, uuid);
    r.io.dev = dev;
    if (call(DM_DEV_STATUS, &r) != ENXIO) die("DM_DEV_STATUS by uuid and number", errno, 0);
    start(&r, NULL, 0);
    r.io.dev = makedev(major(dev), 1000);
    if (call(DM_DEV_STATUS, &r) != ENXIO) die("DM_DEV_STATUS by a number no device has", errno, 0);
    start(&r, NULL, 0);
    r.io.dev = makedev(1, 3);
    if (call(DM_DEV_STATUS, &r) != ENXIO) die("DM_DEV_STATUS by another driver's number", errno, 0);
    start(&r, NULL, 0);
    if (call(DM_DEV_STATUS, &r) != ENXIO) die("DM_DEV_STATUS by nothing", errno, 0);
    start(&r, "gex-dm-nothing", 0);
    if (call(DM_DEV_STATUS, &r) != ENXIO) die("DM_DEV_STATUS of nothing", errno, 0);
    // Listed.
    start(&r, NULL, 0);
    if (call(DM_LIST_DEVICES, &r)) die("DM_LIST_DEVICES", errno, 0);
    int listed = 0;
    for (struct dm_name_list *n = (struct dm_name_list *)(r.bytes + r.io.data_start);; n = (struct dm_name_list *)((char *)n + n->next)) {
        if (n->dev == dev && !strcmp(n->name, name)) listed++;
        if (!n->next) break;
    }
    if (listed != 1) die("the device in the list", listed, 0);

    // It has a number and no disk yet: its node does not open, and sysfs
    // has nothing of it, until it is given a table.
    if (mknod(in(top, "dm"), S_IFBLK | 0600, dev)) die("mknod of the device", errno, 0);
    int fd = open(in(top, "dm"), O_RDONLY);
    if (fd >= 0 || errno != ENXIO) die("a device with no table, opened", fd, 0);
    char path[128], text[128];
    struct stat st;
    snprintf(path, sizeof path, "block/dm-%u", minor(dev));
    if (lstat(in(sys, path), &st) == 0 || errno != ENOENT) die("a device with no table, in sysfs", errno, 0);

    // What is not a table.
    char words[64];
    snprintf(words, sizeof words, "7:%d 16", number);
    start(&r, name, 0);
    target(&r, 0, 100, "nosuchtarget", "");
    if (call(DM_TABLE_LOAD, &r) != EINVAL) die("a target type there is not", errno, 0);
    start(&r, name, 0);
    target(&r, 8, 100, "zero", "");
    if (call(DM_TABLE_LOAD, &r) != EINVAL) die("a table that does not start at 0", errno, 0);
    start(&r, name, 0);
    target(&r, 0, 100, "linear", "240:5 0");
    if (call(DM_TABLE_LOAD, &r) != ENXIO) die("a linear target of no device", errno, 0);
    start(&r, name, 0);
    target(&r, 0, 100, "linear", "nonsense");
    if (call(DM_TABLE_LOAD, &r) != EINVAL) die("a linear target with no offset", errno, 0);

    // A table: 1000 sectors of the loop device from its sector 16, then
    // 24 of zeros. It waits until the device is resumed.
    start(&r, name, 0);
    target(&r, 0, 1000, "linear", words);
    target(&r, 1000, 24, "zero", "");
    if (call(DM_TABLE_LOAD, &r) || !(r.io.flags & DM_INACTIVE_PRESENT_FLAG) || (r.io.flags & DM_ACTIVE_PRESENT_FLAG)) die("DM_TABLE_LOAD", errno, r.io.flags);
    fd = open(in(top, "dm"), O_RDONLY);
    if (fd < 0 || size_of(fd) != 0) die("a device whose table waits", errno, 0);
    snprintf(path, sizeof path, "block/dm-%u/dm/name", minor(dev));
    snprintf(text, sizeof text, "%s\n", name);
    reads(path, text);
    snprintf(path, sizeof path, "block/dm-%u/dm/uuid", minor(dev));
    snprintf(text, sizeof text, "%s\n", uuid);
    reads(path, text);
    snprintf(path, sizeof path, "block/dm-%u/dev", minor(dev));
    snprintf(text, sizeof text, "%u:%u\n", major(dev), minor(dev));
    reads(path, text);
    snprintf(path, sizeof path, "block/dm-%u/size", minor(dev));
    reads(path, "0\n");
    start(&r, name, 0);
    if (call(DM_DEV_SUSPEND, &r) || !(r.io.flags & DM_ACTIVE_PRESENT_FLAG) || (r.io.flags & (DM_INACTIVE_PRESENT_FLAG | DM_SUSPEND_FLAG)) || r.io.target_count != 2) die("the resume that takes the table", errno, r.io.flags);
    if (size_of(fd) != 1024 * 512) die("the device's size", size_of(fd), 0);
    static unsigned char buf[8192];
    if (pread(fd, buf, 4096, 0) != 4096 || memcmp(buf, data + 16 * 512, 4096)) die("a read of the linear part", errno, 0);
    if (pread(fd, buf, 1024, 999 * 512) != 1024 || memcmp(buf, data + (16 + 999) * 512, 512)) die("a read across the two targets", errno, 0);
    for (int i = 512; i < 1024; i++) {
        if (buf[i]) die("the zero target", i, buf[i]);
    }
    if (pread(fd, buf, 512, 1024 * 512) != 0) die("a read past the end", errno, 0);
    snprintf(path, sizeof path, "block/dm-%u/size", minor(dev));
    reads(path, "1024\n");
    snprintf(path, sizeof path, "block/dm-%u/dm/suspended", minor(dev));
    reads(path, "0\n");
    snprintf(path, sizeof path, "block/dm-%u/slaves/loop%d", minor(dev), number);
    if (lstat(in(sys, path), &st) || !S_ISLNK(st.st_mode)) die("the device it is made of, in sysfs", errno, 0);

    // The table read back, and what it is made of.
    start(&r, name, DM_STATUS_TABLE_FLAG);
    if (call(DM_TABLE_STATUS, &r) || r.io.target_count != 2) die("DM_TABLE_STATUS", errno, r.io.target_count);
    struct dm_target_spec *spec = (struct dm_target_spec *)(r.bytes + r.io.data_start);
    if (spec->sector_start != 0 || spec->length != 1000 || strcmp(spec->target_type, "linear") || strcmp((char *)(spec + 1), words)) {
        printf("dmctl: the first target reads back '%s' '%s'\n", spec->target_type, (char *)(spec + 1));
        return 1;
    }
    spec = (struct dm_target_spec *)(r.bytes + r.io.data_start + spec->next);
    if (spec->sector_start != 1000 || spec->length != 24 || strcmp(spec->target_type, "zero")) die("the second target read back", spec->sector_start, spec->length);
    start(&r, name, 0);
    if (call(DM_TABLE_DEPS, &r)) die("DM_TABLE_DEPS", errno, 0);
    struct dm_target_deps *deps = (struct dm_target_deps *)(r.bytes + r.io.data_start);
    if (deps->count != 1 || major(deps->dev[0]) != 7 || minor(deps->dev[0]) != (unsigned)number) die("what the table is made of", deps->count, deps->dev[0]);

    // Suspended, and resumed.
    start(&r, name, DM_SUSPEND_FLAG);
    if (call(DM_DEV_SUSPEND, &r) || !(r.io.flags & DM_SUSPEND_FLAG)) die("DM_DEV_SUSPEND", errno, r.io.flags);
    snprintf(path, sizeof path, "block/dm-%u/dm/suspended", minor(dev));
    reads(path, "1\n");
    start(&r, name, 0);
    if (call(DM_DEV_SUSPEND, &r) || (r.io.flags & DM_SUSPEND_FLAG)) die("the resume", errno, r.io.flags);

    // Another table takes its place at the next resume. (It is not read:
    // what was read through the first may still be remembered.)
    start(&r, name, DM_READONLY_FLAG);
    target(&r, 0, 8, "error", "");
    if (call(DM_TABLE_LOAD, &r) || !(r.io.flags & DM_INACTIVE_PRESENT_FLAG) || !(r.io.flags & DM_ACTIVE_PRESENT_FLAG)) die("a second table", errno, r.io.flags);
    if (size_of(fd) != 1024 * 512) die("the size while a second table waits", size_of(fd), 0);
    start(&r, name, 0);
    if (call(DM_TABLE_CLEAR, &r) || (r.io.flags & DM_INACTIVE_PRESENT_FLAG)) die("DM_TABLE_CLEAR", errno, r.io.flags);
    start(&r, name, DM_READONLY_FLAG);
    target(&r, 0, 8, "error", "");
    if (call(DM_TABLE_LOAD, &r)) die("the second table again", errno, 0);
    start(&r, name, 0);
    if (call(DM_DEV_SUSPEND, &r) || r.io.target_count != 1 || !(r.io.flags & DM_READONLY_FLAG)) die("the resume that takes the second table", errno, r.io.flags);
    if (size_of(fd) != 8 * 512) die("the size of the second table", size_of(fd), 0);
    int ro = 0;
    if (ioctl(fd, BLKROGET, &ro) || ro != 1) die("a read-only table's device", ro, 0);

    // Taken away: not while it is open.
    start(&r, name, 0);
    if (call(DM_DEV_REMOVE, &r) != EBUSY) die("removing a device that is open", errno, 0);
    close(fd);
    int e = EBUSY;
    for (int tries = 0; tries < 300 && e == EBUSY; tries++) {
        start(&r, name, 0);
        e = call(DM_DEV_REMOVE, &r);
        if (e == EBUSY) usleep(10000);
    }
    if (e) die("DM_DEV_REMOVE", e, 0);
    start(&r, name, 0);
    if (call(DM_DEV_STATUS, &r) != ENXIO || call(DM_DEV_REMOVE, &r) != ENXIO) die("a device that is gone", errno, 0);
    snprintf(path, sizeof path, "block/dm-%u", minor(dev));
    if (lstat(in(sys, path), &st) == 0) die("a removed device in sysfs", 0, 0);

    // An error target reads as an error.
    char failing[64];
    snprintf(failing, sizeof failing, "gex-dm-error-%d", getpid());
    start(&r, failing, 0);
    if (call(DM_DEV_CREATE, &r)) die("a second device", errno, 0);
    uint64_t dev2 = r.io.dev;
    start(&r, failing, 0);
    target(&r, 0, 8, "error", "");
    if (call(DM_TABLE_LOAD, &r)) die("an error table", errno, 0);
    start(&r, failing, 0);
    if (call(DM_DEV_SUSPEND, &r) || mknod(in(top, "dm2"), S_IFBLK | 0600, dev2)) die("the second device", errno, 0);
    fd = open(in(top, "dm2"), O_RDONLY);
    if (fd < 0 || size_of(fd) != 8 * 512) die("the second device's size", errno, 0);
    if (pread(fd, buf, 512, 0) >= 0 || errno != EIO) die("a read of an error target", errno, 0);
    close(fd);
    e = EBUSY;
    for (int tries = 0; tries < 300 && e == EBUSY; tries++) {
        start(&r, failing, 0);
        e = call(DM_DEV_REMOVE, &r);
        if (e == EBUSY) usleep(10000);
    }
    if (e) die("removing the second device", e, 0);

    // As apexd does for every APEX: a device with a name and nothing else.
    snprintf(name, sizeof name, "com.example.gex%d", getpid());
    start(&r, name, 0);
    if (call(DM_DEV_CREATE, &r)) die("a placeholder device", errno, 0);
    start(&r, name, 0);
    if (call(DM_DEV_STATUS, &r) || (r.io.flags & (DM_ACTIVE_PRESENT_FLAG | DM_INACTIVE_PRESENT_FLAG))) die("a placeholder's status", errno, r.io.flags);
    start(&r, name, 0);
    if (call(DM_DEV_REMOVE, &r)) die("removing the placeholder", errno, 0);

    // The targets there are.
    start(&r, NULL, 0);
    if (call(DM_LIST_VERSIONS, &r)) die("DM_LIST_VERSIONS", errno, 0);
    int linear = 0;
    for (struct dm_target_versions *v = (struct dm_target_versions *)(r.bytes + r.io.data_start);; v = (struct dm_target_versions *)((char *)v + v->next)) {
        linear += !strcmp(v->name, "linear");
        if (!v->next) break;
    }
    if (linear != 1) die("linear among the targets", linear, 0);

    if (ioctl(loop, LOOP_CLR_FD)) die("LOOP_CLR_FD", errno, 0);
    close(loop);
    close(lctl);
    close(ctl);
    close(file);
    for (int tries = 0; tries < 300 && umount(top); tries++) usleep(10000);
    if (umount(sys) || rmdir(sys) || rmdir(top)) die("umount", errno, 0);
    printf("dmctl ok\n");
    return 0;
}
