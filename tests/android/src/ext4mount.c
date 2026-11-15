// An ext4 image mounted from a loop device, as Android's apexd mounts
// each APEX's payload: the image is in a larger file at an offset (an
// APEX stores its payload in a zip, uncompressed), a loop device is put
// over that part of the file, and the device is mounted read-only.
//
// The image is the kernel crate's fixture
// (crates/gex-kernel/src/vfs/testdata/ext4/apex.img), made as apexer
// makes a payload; what is in it is what Linux's ext4 showed
// (apex.txt beside it).
//
// - mount -t ext4 of the device, read-only: its files read as they are,
//   with their sizes, modes, link counts and times; a file with holes
//   reads zeros in them; two names of one file are one inode.
// - Symbolic links: a short one, a long one, an absolute one; a path
//   through a link to a directory beside it.
// - A directory lists what is in it; one of several blocks, all of it.
// - Extended attributes: a file's SELinux label, one kept in the inode
//   and one in a block of its own, and the list of them.
// - A device node in it opens as the device. (apexd mounts nodev, where
//   it would not: gex does not keep that flag yet, so it is not asked.)
// - Nothing can be changed (EROFS), and statfs says ext4.
// - What is not an ext4 does not mount (EINVAL), nor does a regular file
//   in place of the device (ENOTBLK); a read-only device mounted for
//   writing is EACCES.
// - Unmounted, a device that clears itself lets go of the file.
//
// Needs root; without it the program says so and exits 77.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef EXT4_IMAGE
#error "build with -DEXT4_IMAGE=\"<path to apex.img>\""
#endif
__asm__(".section .rodata\n"
        ".global ext4_image\n"
        "ext4_image:\n"
        ".incbin \"" EXT4_IMAGE "\"\n"
        ".global ext4_image_end\n"
        "ext4_image_end:\n"
        ".previous\n");
extern const char ext4_image[], ext4_image_end[];

#define OFFSET 12288

static char top[64], mnt[96];

static void die(const char *what, long a, long b) {
    printf("ext4mount: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *in(const char *dir, const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", dir, path);
    return out;
}

static uint64_t fnv(const unsigned char *data, size_t n) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) h = (h ^ data[i]) * 0x100000001b3ull;
    return h;
}

// A file's size and the checksum of its bytes, as apex.txt has them.
static void file_is(const char *path, long size, uint64_t sum) {
    static unsigned char buf[1 << 17];
    int fd = open(in(mnt, path), O_RDONLY);
    if (fd < 0) die(path, errno, 0);
    long n = 0, got;
    while ((got = read(fd, buf + n, sizeof buf - n)) > 0) n += got;
    close(fd);
    if (got < 0 || n != size || fnv(buf, n) != sum) die(path, n, got);
}

static void link_is(const char *path, const char *want) {
    char target[256] = {0};
    if (readlink(in(mnt, path), target, sizeof target - 1) < 0 || strcmp(target, want)) {
        printf("ext4mount: %s leads to '%s' (errno %d)\n", path, target, errno);
        exit(1);
    }
}

static void attr_is(const char *path, const char *name, const char *want) {
    char value[512] = {0};
    ssize_t n = lgetxattr(in(mnt, path), name, value, sizeof value - 1);
    if (n != (ssize_t)strlen(want) || memcmp(value, want, n)) {
        printf("ext4mount: %s of %s is '%s' (%zd, errno %d)\n", name, path, value, n, errno);
        exit(1);
    }
}

// A loop device over the image in `file`, cleared at its last close; its
// number.
static int loop_over(int ctl, int file, int flags) {
    for (int tries = 0; tries < 20; tries++) {
        int number = ioctl(ctl, LOOP_CTL_GET_FREE);
        if (number < 0) die("LOOP_CTL_GET_FREE", errno, 0);
        unlink(in(top, "loop"));
        if (mknod(in(top, "loop"), S_IFBLK | 0600, makedev(7, number))) die("mknod", errno, 0);
        int dev = open(in(top, "loop"), O_RDWR);
        if (dev < 0) die("open of the loop device", errno, 0);
        struct loop_config config;
        memset(&config, 0, sizeof config);
        config.fd = file;
        config.block_size = 4096;
        config.info.lo_offset = OFFSET;
        config.info.lo_sizelimit = ext4_image_end - ext4_image;
        config.info.lo_flags = flags;
        if (ioctl(dev, LOOP_CONFIGURE, &config) == 0) return dev;
        // Another took it first.
        if (errno != EBUSY) die("LOOP_CONFIGURE", errno, 0);
        close(dev);
    }
    die("no loop device to be had", 0, 0);
    return -1;
}

int main(void) {
    if (geteuid() != 0) {
        printf("ext4mount: needs root\n");
        return 77;
    }
    strcpy(top, "/tmp/ext4mount-XXXXXX");
    if (!mkdtemp(top) || mount("tmpfs", top, "tmpfs", 0, NULL)) die("a tmpfs", errno, 0);
    snprintf(mnt, sizeof mnt, "%s/mnt", top);
    if (mkdir(mnt, 0755) || mknod(in(top, "control"), S_IFCHR | 0600, makedev(10, 237))) die("mkdir", errno, 0);
    int ctl = open(in(top, "control"), O_RDWR);
    if (ctl < 0) die("the loop control", errno, 0);

    // The image, in a file, after something else.
    long size = ext4_image_end - ext4_image;
    int file = open(in(top, "package"), O_RDWR | O_CREAT, 0600);
    static char junk[OFFSET];
    memset(junk, 'z', sizeof junk);
    if (file < 0 || write(file, junk, OFFSET) != OFFSET || write(file, ext4_image, size) != size || write(file, junk, 100) != 100) die("the file", errno, 0);
    int rfile = open(in(top, "package"), O_RDONLY);
    int dev = loop_over(ctl, rfile, LO_FLAGS_AUTOCLEAR | LO_FLAGS_READ_ONLY);

    // What does not mount.
    if (mount(in(top, "package"), mnt, "ext4", MS_RDONLY, NULL) == 0 || errno != ENOTBLK) die("a regular file in place of a device", errno, 0);
    if (mount(in(top, "nothing"), mnt, "ext4", MS_RDONLY, NULL) == 0 || errno != ENOENT) die("a device that is not there", errno, 0);
    if (mount(in(top, "loop"), mnt, "ext4", 0, NULL) == 0 || errno != EACCES) die("a read-only device mounted for writing", errno, 0);
    if (mount(in(top, "loop"), mnt, "ext4", MS_RDONLY | MS_NOATIME, NULL)) die("mount", errno, 0);
    struct statfs sf;
    if (statfs(mnt, &sf) || sf.f_type != 0xef53) die("statfs", sf.f_type, 0);

    // Its files.
    struct stat st, other;
    file_is("apex_manifest.pb", 39, 0xd13faeaee057b8b5ull);
    file_is("bin/tool", 6393, 0x97d370ab2901a149ull);
    file_is("lib64/libfixture.so", 36393, 0x0db7e255b679f3d5ull);
    file_is("lib64/holes", 40000, 0x9c56a5bd50402d68ull);
    file_is("etc/empty-file", 0, 0xcbf29ce484222325ull);
    file_is("etc/long/nested/deeper/file", 5, fnv((const unsigned char *)"deep\n", 5));
    if (stat(in(mnt, "bin/tool"), &st) || (st.st_mode & 07777) != 0755 || !S_ISREG(st.st_mode) || st.st_nlink != 2 || st.st_mtime != 1767323045) die("bin/tool", st.st_mode, st.st_mtime);
    if (stat(in(mnt, "bin/tool2"), &other) || other.st_ino != st.st_ino) die("two names of one file", st.st_ino, other.st_ino);
    if (stat(in(mnt, "lib64/holes"), &st) || (st.st_mode & 07777) != 04755 || st.st_size != 40000) die("lib64/holes", st.st_mode, st.st_size);
    if (stat(in(mnt, "etc/long"), &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 07777) != 0750) die("etc/long", st.st_mode, 0);
    if (stat(in(mnt, "apex_manifest.pb"), &st) || st.st_mtime != 1000000000) die("a time", st.st_mtime, 0);
    // A read from the middle, across a block.
    char buf[64];
    int fd = open(in(mnt, "bin/tool"), O_RDONLY);
    if (fd < 0 || pread(fd, buf, 9, 4090) != 9 || memcmp(buf, "40\n1041\n1", 9)) die("a read across a block", errno, 0);
    close(fd);

    // Links.
    link_is("bin/short", "tool");
    link_is("etc/abs", "/system/bin/sh");
    link_is("etc/long-link", "../lib64/a-name-long-enough-that-the-link-does-not-fit-in-the-inode-and-takes-a-block-of-its-own/libfixture.so");
    if (lstat(in(mnt, "bin/short"), &st) || !S_ISLNK(st.st_mode) || st.st_size != 4) die("lstat of a link", st.st_mode, st.st_size);
    if (stat(in(mnt, "bin/short"), &st) || st.st_size != 6393) die("a link followed", st.st_size, errno);

    // Directories.
    int entries = 0, dots = 0;
    DIR *d = opendir(in(mnt, "many"));
    if (!d) die("opendir", errno, 0);
    for (struct dirent *e; (e = readdir(d));) {
        if (e->d_name[0] == '.') dots++;
        else if (!strncmp(e->d_name, "an-entry-with-a-long-name-to-fill-the-block-", 44) && e->d_type == DT_REG) entries++;
    }
    closedir(d);
    if (entries != 150 || dots != 2) die("a directory of several blocks", entries, dots);
    if (stat(in(mnt, "etc/long/nested/../nested/deeper/file"), &st)) die("a path with ..", errno, 0);
    if (stat(in(mnt, "bin/tool/x"), &st) == 0 || errno != ENOTDIR) die("a name under a file", errno, 0);
    if (stat(in(mnt, "bin/nothing"), &st) == 0 || errno != ENOENT) die("a name that is not there", errno, 0);

    // Attributes.
    attr_is("bin/tool", "security.selinux", "u:object_r:system_linker_exec:s0");
    attr_is("bin/tool", "user.comment", "a comment");
    attr_is("lib64/libfixture.so", "security.selinux", "u:object_r:system_file:s0");
    char big[512] = {0}, names[256] = {0};
    ssize_t n = lgetxattr(in(mnt, "lib64/libfixture.so"), "user.big", big, sizeof big);
    if (n != 372 || strncmp(big, "1 2 3 4 5 ", 10)) die("an attribute in a block of its own", n, errno);
    n = llistxattr(in(mnt, "bin/tool"), names, sizeof names);
    if (n != 30 || !memmem(names, n, "security.selinux", 17) || !memmem(names, n, "user.comment", 13)) die("the list of attributes", n, errno);
    if (lgetxattr(in(mnt, "bin/tool"), "user.nothing", big, sizeof big) >= 0 || errno != ENODATA) die("an attribute that is not there", errno, 0);

    // A device node.
    if (stat(in(mnt, "etc/null"), &st) || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3)) die("a device node", st.st_mode, st.st_rdev);
    if (stat(in(mnt, "etc/disk"), &st) || !S_ISBLK(st.st_mode) || st.st_rdev != makedev(7, 0)) die("a block device node", st.st_mode, st.st_rdev);
    if (stat(in(mnt, "etc/pipe"), &st) || !S_ISFIFO(st.st_mode)) die("a FIFO", st.st_mode, 0);
    fd = open(in(mnt, "etc/null"), O_RDONLY);
    if (fd < 0 || read(fd, buf, sizeof buf) != 0) die("a device node opened", errno, 0);
    close(fd);

    // Nothing changes.
    if (open(in(mnt, "bin/tool"), O_WRONLY) >= 0 || errno != EROFS) die("open for writing", errno, 0);
    if (open(in(mnt, "bin/new"), O_WRONLY | O_CREAT, 0644) >= 0 || errno != EROFS) die("a new file", errno, 0);
    if (mkdir(in(mnt, "newdir"), 0755) == 0 || errno != EROFS) die("mkdir", errno, 1);
    if (unlink(in(mnt, "bin/tool")) == 0 || errno != EROFS) die("unlink", errno, 0);
    if (rename(in(mnt, "bin/tool"), in(mnt, "bin/other")) == 0 || errno != EROFS) die("rename", errno, 0);
    if (chmod(in(mnt, "bin/tool"), 0700) == 0 || errno != EROFS) die("chmod", errno, 0);
    if (lsetxattr(in(mnt, "bin/tool"), "user.x", "1", 1, 0) == 0 || errno != EROFS) die("setxattr", errno, 0);

    // Unmounted, the device (closed here already) lets go of the file.
    close(dev);
    struct loop_info64 info;
    dev = open(in(top, "loop"), O_RDONLY);
    if (dev < 0 || ioctl(dev, LOOP_GET_STATUS64, &info)) die("the device while mounted", errno, 0);
    close(dev);
    if (umount(mnt)) die("umount", errno, 0);
    int unbound = 0;
    for (int tries = 0; tries < 300 && !unbound; tries++) {
        dev = open(in(top, "loop"), O_RDONLY);
        if (dev >= 0) {
            unbound = ioctl(dev, LOOP_GET_STATUS64, &info) && errno == ENXIO;
            close(dev);
        }
        if (!unbound) usleep(10000);
    }
    if (!unbound) die("the device after umount", 0, 0);

    // What is not an ext4: the same file from its start.
    dev = loop_over(ctl, rfile, LO_FLAGS_AUTOCLEAR | LO_FLAGS_READ_ONLY);
    struct loop_info64 moved;
    memset(&moved, 0, sizeof moved);
    moved.lo_flags = LO_FLAGS_AUTOCLEAR;
    if (ioctl(dev, LOOP_SET_STATUS64, &moved)) die("LOOP_SET_STATUS64", errno, 0);
    if (mount(in(top, "loop"), mnt, "ext4", MS_RDONLY, NULL) == 0 || errno != EINVAL) die("what is not an ext4", errno, 0);
    close(dev);

    close(ctl);
    close(file);
    close(rfile);
    for (int tries = 0; tries < 300 && umount(top); tries++) usleep(10000);
    if (rmdir(top)) die("umount", errno, 1);
    printf("ext4mount ok\n");
    return 0;
}
