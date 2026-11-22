// The hypervisor consoles (hvc_console, with virtio_console behind it) as a
// guest of a virtual machine has them, the Android emulator's among them
// (its goldfish-logcat writes to /dev/hvc1): the driver registers a device
// for each of its eight minors when it loads, at
// /sys/devices/virtual/tty/hvcN, numbered 229:N; a minor with a port behind
// it opens as a terminal, one without is ENODEV. On an open port a read with
// nothing typed is EAGAIN without blocking, poll says only writable, and a
// write is taken whole. Without hvc consoles the program says so and exits
// 77. Run as root (it mounts a sysfs of its own, and makes the nodes in a
// tmpfs of its own).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static void die(const char *what, const char *path) {
    printf("hvc: %s (%s; errno %d)\n", what, path, errno);
    exit(1);
}

static void slurp(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die("cannot open", path);
    ssize_t r = read(fd, buf, n - 1);
    if (r < 0) die("cannot read", path);
    buf[r] = 0;
    close(fd);
}

int main(void) {
    char sys[] = "/tmp/hvc-sys-XXXXXX";
    if (!mkdtemp(sys)) die("mkdtemp", sys);
    if (mount("sysfs", sys, "sysfs", 0, NULL)) die("mount sysfs", sys);
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/class/tty/hvc0", sys);
    if (access(path, F_OK)) {
        umount(sys);
        rmdir(sys);
        printf("hvc: no hvc consoles\n");
        return 77;
    }
    char dir[] = "/tmp/hvc-test-XXXXXX";
    if (!mkdtemp(dir)) die("mkdtemp", dir);
    if (mount("tmpfs", dir, "tmpfs", 0, NULL)) die("mount tmpfs", dir);
    int ports = 0;
    for (int n = 0; n < 8; n++) {
        char real[PATH_MAX], buf[512], want[PATH_MAX];
        snprintf(path, sizeof path, "%s/class/tty/hvc%d", sys, n);
        if (!realpath(path, real)) die("no class link for a minor", path);
        snprintf(want, sizeof want, "%s/devices/virtual/tty/hvc%d", sys, n);
        if (strcmp(real, want)) die("not a virtual device", real);
        snprintf(path, sizeof path, "%s/class/tty/hvc%d/dev", sys, n);
        slurp(path, buf, sizeof buf);
        snprintf(want, sizeof want, "229:%d\n", n);
        if (strcmp(buf, want)) die("wrong number", path);
        snprintf(path, sizeof path, "%s/class/tty/hvc%d/uevent", sys, n);
        slurp(path, buf, sizeof buf);
        snprintf(want, sizeof want, "MAJOR=229\nMINOR=%d\nDEVNAME=hvc%d\n", n, n);
        if (strcmp(buf, want)) die("wrong uevent", path);

        snprintf(path, sizeof path, "%s/hvc%d", dir, n);
        if (mknod(path, S_IFCHR | 0600, makedev(229, n))) die("mknod", path);
        int fd = open(path, O_RDWR | O_NONBLOCK | O_NOCTTY);
        if (fd < 0) {
            if (errno != ENODEV) die("a minor without a port is not ENODEV", path);
            continue;
        }
        ports++;
        if (!isatty(fd)) die("not a terminal", path);
        char c;
        if (read(fd, &c, 1) != -1 || errno != EAGAIN) die("a read with nothing typed is not EAGAIN", path);
        struct pollfd p = {fd, POLLIN | POLLOUT, 0};
        if (poll(&p, 1, 0) != 1 || p.revents != POLLOUT) die("poll is not writable alone", path);
        if (write(fd, "\n", 1) != 1) die("a write is not taken", path);
        close(fd);
    }
    if (ports == 0) die("no minor has a port", dir);
    umount(dir);
    rmdir(dir);
    umount(sys);
    rmdir(sys);
    printf("hvc ok\n");
    return 0;
}
