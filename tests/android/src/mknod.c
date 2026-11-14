// mknod: the device nodes an init makes in the tmpfs it mounts on /dev.
//
// - A character device made by number opens as that device wherever its
//   node is: 1:3 swallows writes and reads as empty, 1:5 reads zeros, 1:7
//   is full, 1:8 and 1:9 read random bytes. Its node says what it is: a
//   character device, its number, its mode less the umask; and so does
//   the device once open.
// - A number no device has opens as ENXIO; the node is there all the same.
// - A regular file made by mknod is empty; a name that is taken is
//   EEXIST; a directory cannot be made this way (EPERM); a name in no
//   directory is ENOENT. A device node is removed like any other.
//
// Needs the right to mount a tmpfs and make device nodes (root); without
// it the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static char dir[64];

static void die(const char *what, long a, long b) {
    printf("mknod: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    umount2(dir, MNT_DETACH);
    rmdir(dir);
    exit(1);
}

static const char *in(const char *name) {
    static char path[4][128];
    static int at;
    char *p = path[at++ & 3];
    snprintf(p, 128, "%s/%s", dir, name);
    return p;
}

// Make a character device and open it.
static int device(const char *name, unsigned major, unsigned minor, int flags) {
    if (mknod(in(name), S_IFCHR | 0666, makedev(major, minor))) die(name, major, minor);
    struct stat st;
    if (stat(in(name), &st) || !S_ISCHR(st.st_mode) || major(st.st_rdev) != major || minor(st.st_rdev) != minor) die("a device's node", st.st_mode, st.st_rdev);
    return open(in(name), flags | O_CLOEXEC);
}

int main(void) {
    snprintf(dir, sizeof dir, "/tmp/mknod-test-%d", getpid());
    if (mkdir(dir, 0755)) {
        printf("mknod: mkdir %s: errno %d\n", dir, errno);
        return 1;
    }
    if (mount("tmpfs", dir, "tmpfs", MS_NOSUID, "mode=0755")) {
        printf("mknod: cannot mount a tmpfs: errno %d\n", errno);
        rmdir(dir);
        return errno == EPERM || errno == EACCES ? 77 : 1;
    }
    umask(022);
    // The right to make a device node is its own (CAP_MKNOD).
    if (mknod(in("probe"), S_IFCHR | 0600, makedev(1, 3))) {
        printf("mknod: cannot make a device node: errno %d\n", errno);
        int may_not = errno == EPERM;
        umount2(dir, MNT_DETACH);
        rmdir(dir);
        return may_not ? 77 : 1;
    }
    if (unlink(in("probe"))) die("unlink the probe", 0, 0);
    char buf[64];
    struct stat st;

    // The memory devices, by number.
    int fd = device("null", 1, 3, O_RDWR);
    if (fd < 0 || write(fd, "x", 1) != 1 || read(fd, buf, sizeof buf) != 0) die("1:3, null", fd, 0);
    if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || (st.st_mode & 07777) != 0644 || st.st_rdev != makedev(1, 3)) die("null's node, open", st.st_mode, st.st_rdev);
    close(fd);
    fd = device("zero", 1, 5, O_RDONLY);
    memset(buf, 'x', sizeof buf);
    if (fd < 0 || read(fd, buf, sizeof buf) != sizeof buf || buf[0] || buf[63]) die("1:5, zero", fd, buf[0]);
    close(fd);
    fd = device("full", 1, 7, O_RDWR);
    if (fd < 0 || write(fd, "x", 1) != -1 || errno != ENOSPC) die("1:7, full", fd, 0);
    close(fd);
    for (unsigned minor = 8; minor <= 9; minor++) {
        fd = device(minor == 8 ? "random" : "urandom", 1, minor, O_RDONLY);
        memset(buf, 0, sizeof buf);
        int nonzero = 0;
        if (fd < 0 || read(fd, buf, sizeof buf) != sizeof buf) die("random bytes", fd, minor);
        for (size_t i = 0; i < sizeof buf; i++) nonzero += buf[i] != 0;
        if (nonzero < 32) die("bytes that are not random", nonzero, minor);
        close(fd);
    }
    // A number no driver has: the node is made, and does not open.
    fd = device("nothing", 240, 77, O_RDONLY);
    if (fd != -1 || errno != ENXIO) die("a device nobody has", fd, errno);

    // A regular file, and what cannot be made.
    if (mknod(in("file"), S_IFREG | 0640, 0) || stat(in("file"), &st) || !S_ISREG(st.st_mode) || st.st_size != 0 || (st.st_mode & 07777) != 0640) die("a regular file", st.st_mode, st.st_size);
    if (mknod(in("file"), S_IFREG | 0640, 0) != -1 || errno != EEXIST) die("a name that is taken", errno, 0);
    if (mknod(in("null"), S_IFCHR | 0666, makedev(1, 3)) != -1 || errno != EEXIST) die("a device name that is taken", errno, 0);
    if (mknod(in("sub"), S_IFDIR | 0755, 0) != -1 || errno != EPERM) die("a directory", errno, 0);
    if (mknod(in("no/such/dir"), S_IFREG | 0644, 0) != -1 || errno != ENOENT) die("a name in no directory", errno, 0);
    if (unlink(in("null")) || stat(in("null"), &st) != -1) die("unlink of a device", 0, 0);

    if (umount(dir)) die("umount", 0, 0);
    if (rmdir(dir)) die("rmdir", 0, 0);
    printf("mknod ok\n");
    return 0;
}
