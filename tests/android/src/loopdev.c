// Loop devices: a file as a disk, which is how Android's apexd puts an
// APEX's payload image where mount can take it.
//
// - /dev/loop-control (10:237) answers a free device's number, adds the
//   device of a number (EEXIST for one there), and takes one away that
//   has no file and is not open (EBUSY, ENODEV). Opening a node with a
//   loop device's number makes the device if it is not there; a number
//   no driver has is ENXIO.
// - A device with no file is a disk of size 0, and the calls about its
//   file are ENXIO.
// - LOOP_CONFIGURE puts a file behind it from an offset, for no more
//   than a limit, with a block size: the device reads and writes the
//   file there, is that long (in whole sectors), and says so through the
//   block layer's calls, lseek, LOOP_GET_STATUS64 and sysfs
//   (block/loop<n>/size, loop/backing_file and the rest). A `change`
//   event tells of it. A second file is EBUSY; a descriptor that is not
//   one, EBADF; a directory, a flag or a block size it does not have,
//   EINVAL.
// - LOOP_SET_STATUS64 moves the offset and limit; LOOP_SET_BLOCK_SIZE the
//   block size.
// - A file opened only for reading, or the read-only flag, makes a
//   read-only device: a write is EPERM.
// - LOOP_CLR_FD takes the file away at the device's last close, and so
//   does a device configured to clear itself.
//
// The nodes are the test's own, in a tmpfs it mounts, by the devices'
// numbers; sysfs is mounted by it too. On a real kernel udev looks at a
// loop device whenever it changes, so what depends on the test's being
// the only opener is waited for and not timed.
//
// Needs root; without it the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define FILE_SIZE ((1 << 20) + 4096 + 300)

static char top[64], sys[64];
static int number;

static void die(const char *what, long a, long b) {
    printf("loopdev: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *in(const char *dir, const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", dir, path);
    return out;
}

// A file of the device's in sysfs: block/loop<n>/<name>.
static const char *attr(const char *name) {
    static char path[128];
    snprintf(path, sizeof path, "block/loop%d/%s", number, name);
    return in(sys, path);
}

static void reads(const char *name, const char *want) {
    char text[256] = {0};
    int fd = open(attr(name), O_RDONLY);
    if (fd < 0) die(name, fd, 0);
    if (read(fd, text, sizeof text - 1) < 0 || strcmp(text, want)) {
        printf("loopdev: %s reads '%s', not '%s'\n", name, text, want);
        exit(1);
    }
    close(fd);
}

static uint64_t size_of(int fd) {
    uint64_t size = 99;
    if (ioctl(fd, BLKGETSIZE64, &size)) die("BLKGETSIZE64", errno, 0);
    return size;
}

// The byte the backing file has at `at`.
static unsigned char byte_at(long at) {
    return (unsigned char)(at * 7 + at / 251);
}

// Whether a `change` event for the device arrives within a while.
static int changed(int s) {
    char want[64], text[4096];
    snprintf(want, sizeof want, "change@/devices/virtual/block/loop%d", number);
    for (int tries = 0; tries < 30; tries++) {
        struct pollfd p = {s, POLLIN, 0};
        if (poll(&p, 1, 100) <= 0) continue;
        ssize_t n = recv(s, text, sizeof text - 1, 0);
        if (n <= 0) continue;
        text[n] = 0;
        if (strcmp(text, want)) continue;
        // Its fields, which are NUL-separated after the first.
        char fields[4096] = {0};
        for (ssize_t i = 0; i < n - 1; i++) fields[i] = text[i] ? text[i] : '|';
        char expect[256];
        snprintf(expect, sizeof expect, "|ACTION=change|DEVPATH=/devices/virtual/block/loop%d|SUBSYSTEM=block|", number);
        char major[64];
        snprintf(major, sizeof major, "|MAJOR=7|MINOR=%d|DEVNAME=loop%d|DEVTYPE=disk|DISKSEQ=", number, number);
        // The kernel's own: no SYNTH_UUID (udev's are synthetic).
        if (strstr(fields, expect) && strstr(fields, major) && !strstr(fields, "SYNTH_UUID")) return 1;
    }
    return 0;
}

// Open the device, waiting out an open that is refused while it is being
// let go of.
static int open_device(int flags) {
    for (int tries = 0; tries < 200; tries++) {
        int fd = open(in(top, "loop"), flags);
        if (fd >= 0) return fd;
        if (errno != ENXIO && errno != EBUSY) die("open of the device", errno, 0);
        usleep(10000);
    }
    die("open of the device", errno, 1);
    return -1;
}

// Wait until the device has no file (udev may still be looking at it).
static void wait_unbound(void) {
    for (int tries = 0; tries < 300; tries++) {
        int fd = open_device(O_RDONLY);
        struct loop_info64 info;
        int unbound = ioctl(fd, LOOP_GET_STATUS64, &info) && errno == ENXIO;
        close(fd);
        if (unbound) return;
        usleep(10000);
    }
    die("the device never let go of its file", 0, 0);
}

int main(void) {
    if (geteuid() != 0) {
        printf("loopdev: needs root\n");
        return 77;
    }
    strcpy(top, "/tmp/loopdev-XXXXXX");
    strcpy(sys, "/tmp/loopdev-sys-XXXXXX");
    if (!mkdtemp(top) || mount("tmpfs", top, "tmpfs", 0, NULL)) die("a tmpfs", errno, 0);
    if (!mkdtemp(sys) || mount("sysfs", sys, "sysfs", 0, NULL)) die("sysfs", errno, 0);

    // The control, by its number.
    if (mknod(in(top, "control"), S_IFCHR | 0600, makedev(10, 237))) die("mknod of the control", errno, 0);
    int ctl = open(in(top, "control"), O_RDWR);
    if (ctl < 0) die("open of the control", errno, 0);
    number = ioctl(ctl, LOOP_CTL_GET_FREE);
    if (number < 0) die("LOOP_CTL_GET_FREE", errno, 0);
    if (ioctl(ctl, LOOP_CTL_ADD, number) >= 0 || errno != EEXIST) die("adding a device that is there", errno, 0);
    if (mknod(in(top, "loop"), S_IFBLK | 0600, makedev(7, number))) die("mknod of the device", errno, 0);
    struct stat st;
    if (stat(in(top, "loop"), &st) || !S_ISBLK(st.st_mode) || st.st_rdev != makedev(7, number)) die("the node", st.st_mode, st.st_rdev);
    if (mknod(in(top, "nothing"), S_IFBLK | 0600, makedev(240, 5)) || open(in(top, "nothing"), O_RDONLY) >= 0 || errno != ENXIO) die("a number no disk has", errno, 0);

    // With no file.
    int dev = open_device(O_RDWR);
    if (fstat(dev, &st) || !S_ISBLK(st.st_mode) || st.st_rdev != makedev(7, number)) die("fstat of the device", st.st_mode, st.st_rdev);
    struct loop_info64 info;
    if (size_of(dev) != 0) die("the size of a device with no file", size_of(dev), 0);
    if (ioctl(dev, LOOP_GET_STATUS64, &info) == 0 || errno != ENXIO) die("LOOP_GET_STATUS64 with no file", errno, 0);
    if (ioctl(dev, LOOP_SET_STATUS64, &info) == 0 || errno != ENXIO) die("LOOP_SET_STATUS64 with no file", errno, 0);
    if (ioctl(dev, LOOP_CLR_FD) == 0 || errno != ENXIO) die("LOOP_CLR_FD with no file", errno, 0);
    if (ioctl(dev, LOOP_SET_BLOCK_SIZE, 4096) == 0 || errno != ENXIO) die("LOOP_SET_BLOCK_SIZE with no file", errno, 0);
    char buf[8192];
    if (pread(dev, buf, 16, 0) != 0) die("a read with no file", errno, 0);
    reads("size", "0\n");
    char text[64];
    snprintf(text, sizeof text, "7:%d\n", number);
    reads("dev", text);
    if (stat(attr("loop"), &st) == 0 || errno != ENOENT) die("the loop directory with no file", errno, 0);
    char target[128], want[128];
    snprintf(text, sizeof text, "block/loop%d", number);
    snprintf(want, sizeof want, "../devices/virtual/block/loop%d", number);
    memset(target, 0, sizeof target);
    if (readlink(in(sys, text), target, sizeof target - 1) < 0 || strcmp(target, want)) die("block/loop<n>", errno, 0);
    snprintf(text, sizeof text, "dev/block/7:%d", number);
    snprintf(want, sizeof want, "../../devices/virtual/block/loop%d", number);
    memset(target, 0, sizeof target);
    if (readlink(in(sys, text), target, sizeof target - 1) < 0 || strcmp(target, want)) die("dev/block/7:<n>", errno, 0);
    if (ioctl(ctl, LOOP_CTL_REMOVE, number) >= 0 || errno != EBUSY) die("removing a device that is open", errno, 0);

    // The file.
    int file = open(in(top, "backing"), O_RDWR | O_CREAT, 0600);
    if (file < 0) die("the file", errno, 0);
    static unsigned char data[FILE_SIZE];
    for (long i = 0; i < FILE_SIZE; i++) data[i] = byte_at(i);
    if (write(file, data, FILE_SIZE) != FILE_SIZE) die("writing the file", errno, 0);

    // What is not a configuration.
    struct loop_config config;
    memset(&config, 0, sizeof config);
    config.fd = -1;
    if (ioctl(dev, LOOP_CONFIGURE, &config) == 0 || errno != EBADF) die("a descriptor that is not one", errno, 0);
    config.fd = file;
    config.info.lo_flags = 0x100;
    if (ioctl(dev, LOOP_CONFIGURE, &config) == 0 || errno != EINVAL) die("a flag there is not", errno, 0);
    config.info.lo_flags = 0;
    config.block_size = 1000;
    if (ioctl(dev, LOOP_CONFIGURE, &config) == 0 || errno != EINVAL) die("a block size that is not one", errno, 0);
    int dir = open(top, O_RDONLY | O_DIRECTORY);
    config.block_size = 0;
    config.fd = dir;
    if (ioctl(dev, LOOP_CONFIGURE, &config) == 0 || errno != EINVAL) die("a directory", errno, 0);
    close(dir);
    if (size_of(dev) != 0) die("the size after what was refused", size_of(dev), 0);

    // Configured: a megabyte of the file from 4096, in 4096-byte blocks.
    int s = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    struct sockaddr_nl nl = {.nl_family = AF_NETLINK, .nl_groups = 1};
    int big = 1 << 20;
    if (s < 0 || setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &big, sizeof big) || bind(s, (struct sockaddr *)&nl, sizeof nl)) die("the uevent socket", s, errno);
    memset(&config, 0, sizeof config);
    config.fd = file;
    config.block_size = 4096;
    config.info.lo_offset = 4096;
    config.info.lo_sizelimit = 1 << 20;
    strcpy((char *)config.info.lo_file_name, "a name for it");
    if (ioctl(dev, LOOP_CONFIGURE, &config)) die("LOOP_CONFIGURE", errno, 0);
    if (!changed(s)) die("no change event at LOOP_CONFIGURE", 0, 0);
    if (ioctl(dev, LOOP_CONFIGURE, &config) == 0 || errno != EBUSY) die("a second file", errno, 0);
    if (ioctl(dev, LOOP_SET_FD, file) == 0 || errno != EBUSY) die("LOOP_SET_FD of a second file", errno, 0);
    if (size_of(dev) != 1 << 20) die("the device's size", size_of(dev), 0);
    unsigned long sectors = 0;
    int ssz = 0, ro = 9;
    if (ioctl(dev, BLKGETSIZE, &sectors) || sectors != 2048 || ioctl(dev, BLKSSZGET, &ssz) || ssz != 4096 || ioctl(dev, BLKROGET, &ro) || ro != 0) die("the block layer's answers", sectors, ssz);
    if (lseek(dev, 0, SEEK_END) != 1 << 20) die("lseek to the device's end", errno, 0);
    if (fstat(dev, &st) || st.st_size != 0) die("fstat's size of a device", st.st_size, 0);
    if (pread(dev, buf, 8192, 0) != 8192 || memcmp(buf, data + 4096, 8192)) die("a read from the start", errno, 0);
    if (pread(dev, buf, 100, 5000) != 100 || memcmp(buf, data + 4096 + 5000, 100)) die("a read from within", errno, 0);
    if (pread(dev, buf, 8192, (1 << 20) - 10) != 10 || memcmp(buf, data + 4096 + (1 << 20) - 10, 10)) die("a read at the end", errno, 0);
    if (pread(dev, buf, 16, 1 << 20) != 0) die("a read past the end", errno, 0);
    // A write goes to the file; one past the end has nowhere to go.
    memset(buf, 0xee, 4096);
    if (pwrite(dev, buf, 4096, 8192) != 4096 || fsync(dev)) die("a write", errno, 0);
    unsigned char back[4096];
    if (pread(file, back, 4096, 4096 + 8192) != 4096 || memcmp(back, buf, 4096)) die("the write in the file", errno, 0);
    if (pwrite(dev, buf, 4096, 1 << 20) >= 0 || errno != ENOSPC) die("a write past the end", errno, 0);
    // What it says of itself.
    memset(&info, 0xff, sizeof info);
    struct stat fst;
    if (ioctl(dev, LOOP_GET_STATUS64, &info) || fstat(file, &fst)) die("LOOP_GET_STATUS64", errno, 0);
    if (info.lo_offset != 4096 || info.lo_sizelimit != 1 << 20 || info.lo_number != (uint32_t)number || info.lo_inode != fst.st_ino) die("the status", info.lo_offset, info.lo_number);
    if ((info.lo_flags & (LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR)) != 0 || strcmp((char *)info.lo_file_name, "a name for it")) die("the status's flags and name", info.lo_flags, 0);
    reads("size", "2048\n");
    reads("ro", "0\n");
    reads("loop/offset", "4096\n");
    reads("loop/sizelimit", "1048576\n");
    reads("loop/autoclear", "0\n");
    snprintf(want, sizeof want, "%s\n", in(top, "backing"));
    reads("loop/backing_file", want);
    reads("queue/logical_block_size", "4096\n");
    // Read-ahead, by the file and by the call: kilobytes and sectors.
    int raf = open(attr("queue/read_ahead_kb"), O_RDWR);
    if (raf < 0 || write(raf, "64", 2) != 2) die("queue/read_ahead_kb", errno, 0);
    close(raf);
    reads("queue/read_ahead_kb", "64\n");
    long ra = 0;
    if (ioctl(dev, BLKRAGET, &ra) || ra != 128) die("BLKRAGET", ra, 0);
    if (ioctl(dev, BLKRASET, 512) || ioctl(dev, BLKFLSBUF, 0)) die("BLKRASET", errno, 0);
    reads("queue/read_ahead_kb", "256\n");
    char sched[128] = {0};
    int sf = open(attr("queue/scheduler"), O_RDONLY);
    if (sf < 0 || read(sf, sched, sizeof sched - 1) <= 0 || !strstr(sched, "[none]")) die("queue/scheduler", errno, 0);
    close(sf);
    // The lowest free device is another now.
    int other = ioctl(ctl, LOOP_CTL_GET_FREE);
    if (other < 0 || other == number) die("a free device while this one has a file", other, number);

    // The offset and limit moved; the block size.
    memset(&info, 0, sizeof info);
    info.lo_offset = 8192;
    if (ioctl(dev, LOOP_SET_STATUS64, &info)) die("LOOP_SET_STATUS64", errno, 0);
    uint64_t rest = (FILE_SIZE - 8192) & ~511ul;
    if (size_of(dev) != rest) die("the size after the offset moved", size_of(dev), rest);
    if (pread(dev, buf, 100, 0) != 100 || memcmp(buf, data + 8192, 100)) die("a read after the offset moved", errno, 0);
    if (ioctl(dev, LOOP_SET_BLOCK_SIZE, 1000) == 0 || errno != EINVAL) die("a block size that is not one", errno, 1);
    if (ioctl(dev, LOOP_SET_BLOCK_SIZE, 512) || ioctl(dev, BLKSSZGET, &ssz) || ssz != 512) die("LOOP_SET_BLOCK_SIZE", errno, ssz);

    // Let go of: at the last close.
    if (ioctl(dev, LOOP_CLR_FD)) die("LOOP_CLR_FD", errno, 0);
    close(dev);
    wait_unbound();
    dev = open_device(O_RDWR);
    if (size_of(dev) != 0) die("the size after LOOP_CLR_FD", size_of(dev), 0);

    // Read-only: by the flag, and by a file opened only for reading. A
    // device that clears itself does so at its last close.
    int rfile = open(in(top, "backing"), O_RDONLY);
    memset(&config, 0, sizeof config);
    config.fd = rfile;
    config.info.lo_flags = LO_FLAGS_AUTOCLEAR;
    if (rfile < 0 || ioctl(dev, LOOP_CONFIGURE, &config)) die("LOOP_CONFIGURE of a file opened for reading", errno, 0);
    if (ioctl(dev, BLKROGET, &ro) || ro != 1 || ioctl(dev, BLKSSZGET, &ssz) || ssz != 512) die("a read-only device", ro, ssz);
    if (size_of(dev) != (FILE_SIZE & ~511ul)) die("the size of a whole file", size_of(dev), 0);
    if (pwrite(dev, buf, 512, 0) >= 0 || errno != EPERM) die("a write to a read-only device", errno, 0);
    if (ioctl(dev, LOOP_GET_STATUS64, &info) || !(info.lo_flags & LO_FLAGS_READ_ONLY) || !(info.lo_flags & LO_FLAGS_AUTOCLEAR)) die("its flags", info.lo_flags, 0);
    reads("ro", "1\n");
    reads("loop/autoclear", "1\n");
    int second = open_device(O_RDONLY);
    close(dev);
    if (size_of(second) != (FILE_SIZE & ~511ul)) die("a device that clears itself, still open", size_of(second), 0);
    close(second);
    wait_unbound();
    dev = open_device(O_RDWR);
    memset(&config, 0, sizeof config);
    config.fd = file;
    config.info.lo_flags = LO_FLAGS_READ_ONLY;
    if (ioctl(dev, LOOP_CONFIGURE, &config)) die("LOOP_CONFIGURE read-only", errno, 0);
    if (pwrite(dev, buf, 512, 0) >= 0 || errno != EPERM) die("a write to a device configured read-only", errno, 0);
    if (ioctl(dev, LOOP_CLR_FD)) die("LOOP_CLR_FD", errno, 1);
    close(dev);
    wait_unbound();

    // A device added and taken away.
    int extra = 700 + getpid() % 200;
    if (ioctl(ctl, LOOP_CTL_ADD, extra) != extra) die("LOOP_CTL_ADD", errno, extra);
    snprintf(text, sizeof text, "block/loop%d/dev", extra);
    if (stat(in(sys, text), &st)) die("an added device in sysfs", errno, 0);
    if (ioctl(ctl, LOOP_CTL_ADD, extra) >= 0 || errno != EEXIST) die("adding it again", errno, 0);
    // udev may be looking at it: busy until it is not.
    int removed = -1;
    for (int tries = 0; tries < 300 && removed != 0; tries++) {
        removed = ioctl(ctl, LOOP_CTL_REMOVE, extra);
        if (removed < 0 && errno != EBUSY) die("LOOP_CTL_REMOVE", errno, 0);
        if (removed < 0) usleep(10000);
    }
    if (removed != 0) die("LOOP_CTL_REMOVE", errno, 1);
    if (ioctl(ctl, LOOP_CTL_REMOVE, extra) >= 0 || errno != ENODEV) die("removing what is not there", errno, 0);
    if (stat(in(sys, text), &st) == 0) die("a removed device in sysfs", 0, 0);
    // A node of a device that is not there makes it, when it is opened.
    if (mknod(in(top, "made"), S_IFBLK | 0600, makedev(7, extra))) die("mknod", errno, 0);
    int made = open(in(top, "made"), O_RDONLY);
    if (made < 0 || stat(in(sys, text), &st) || size_of(made) != 0) die("a device made by opening its node", errno, 0);
    close(made);
    removed = -1;
    for (int tries = 0; tries < 300 && removed != 0; tries++) {
        removed = ioctl(ctl, LOOP_CTL_REMOVE, extra);
        if (removed < 0 && errno != EBUSY) die("LOOP_CTL_REMOVE of the one made", errno, 0);
        if (removed < 0) usleep(10000);
    }
    if (removed != 0) die("LOOP_CTL_REMOVE of the one made", errno, 1);

    close(s);
    close(ctl);
    close(file);
    close(rfile);
    if (umount(sys) || rmdir(sys) || umount(top) || rmdir(top)) die("umount", errno, 0);
    printf("loopdev ok\n");
    return 0;
}
