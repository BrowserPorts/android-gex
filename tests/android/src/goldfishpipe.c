// The emulator's goldfish pipe (common-modules/virtual-device's
// goldfish_pipe.c, misc 10:256 here) and the services the emulator image's
// graphics stack opens on it, as the emulator answers them (aemu's
// AndroidPipe.cpp connector, gfxstream's GLProcessPipe.cpp,
// OpenglEsPipe.cpp and renderControl, aemu's RefcountPipe.cpp):
//
// - a new pipe is a connector: a read is EIO; a connection string that is
//   not "pipe:..." or names no service fails its write with EINVAL; 128
//   bytes with no NUL is EIO; a string sent in parts is taken a part at a
//   time; bytes after the NUL go to the service;
// - GLProcessPipe: the confirmation (100), then the process's id, a 64-bit
//   number from 1, once; a read after that is 0;
// - opengles: the client flags, then renderControl calls answered on the
//   same pipe (the renderer's version 1, the EGL version, the display's
//   width), POLLIN while an answer waits, EAGAIN for a non-blocking read
//   with none;
// - refcount: a color buffer's handle written as four bytes; a read is EIO.
//
// No Linux has this device without the emulator behind it, so the expected
// answers are the sources'. Run as root (mknod) with GEX_EMULATOR_HOST=1.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int failed;
static char node[64];

static void want(const char *what, long r, int err) {
    int got = r >= 0 ? 0 : errno;
    if (got != err) {
        printf("goldfishpipe: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

static void want_eq(const char *what, long long got, long long expect) {
    if (got != expect) {
        printf("goldfishpipe: %s: want %lld, got %lld\n", what, expect, got);
        failed = 1;
    }
}

static int pipe_open(const char *name) {
    int fd = open(node, O_RDWR);
    if (fd < 0) {
        printf("goldfishpipe: open %s: %s\n", node, strerror(errno));
        exit(1);
    }
    if (name) {
        char s[160];
        snprintf(s, sizeof s, "pipe:%s", name);
        long n = write(fd, s, strlen(s) + 1);
        want_eq(name, n, (long long)strlen(s) + 1);
    }
    return fd;
}

// A renderControl call: opcode, its length, then its parameters.
static void call(int fd, uint32_t op, const uint32_t *params, int n) {
    uint32_t buf[16];
    buf[0] = op;
    buf[1] = 8 + 4 * n;
    memcpy(buf + 2, params, 4 * n);
    want_eq("a call's write", write(fd, buf, buf[1]), buf[1]);
}

static void read_all(int fd, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        long n = read(fd, (char *)buf + got, len - got);
        if (n <= 0) {
            printf("goldfishpipe: an answer's read: %ld (%s)\n", n, strerror(errno));
            failed = 1;
            return;
        }
        got += n;
    }
}

int main(void) {
    char base[] = "/tmp/goldfishpipe-XXXXXX", sys[80], dev[160];
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("goldfishpipe: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(sys, sizeof sys, "%s/sys", base);
    snprintf(node, sizeof node, "%s/goldfish_pipe_dprctd", base);
    if (mkdir(sys, 0755) || mount("sysfs", sys, "sysfs", 0, NULL) || mknod(node, S_IFCHR | 0666, makedev(10, 256))) {
        printf("goldfishpipe: setup (errno %d)\n", errno);
        return 1;
    }
    // The misc device, as misc_register adds one with no parent.
    snprintf(dev, sizeof dev, "%s/class/misc/goldfish_pipe_dprctd/dev", sys);
    int d = open(dev, O_RDONLY);
    char num[16] = {0};
    if (d < 0 || read(d, num, sizeof num - 1) <= 0 || strcmp(num, "10:256\n")) {
        printf("goldfishpipe: %s: '%s' (errno %d)\n", dev, num, errno);
        failed = 1;
    }
    if (d >= 0) {
        close(d);
    }

    // The connector.
    int fd = pipe_open(NULL);
    char b[256];
    want("read a connector", read(fd, b, 4), EIO);
    want("an empty write", write(fd, b, 0), 0);
    want("not pipe:", write(fd, "opengles", 9), EINVAL);
    want("the name stays", write(fd, "pipe:opengles", 14), EINVAL);
    close(fd);
    fd = pipe_open(NULL);
    want("no such service", write(fd, "pipe:nosuch", 12), EINVAL);
    close(fd);
    fd = pipe_open(NULL);
    memset(b, 'x', sizeof b);
    want_eq("100 bytes of a name", write(fd, b, 100), 100);
    want("128 with no NUL", write(fd, b, 28), EIO);
    close(fd);

    // GLProcessPipe, its name sent in two parts.
    fd = pipe_open(NULL);
    want_eq("a name's first part", write(fd, "pipe:GLPro", 10), 10);
    want_eq("its rest", write(fd, "cessPipe", 9), 9);
    int32_t confirm = 100;
    want_eq("confirm", write(fd, &confirm, 4), 4);
    uint64_t puid = 0;
    want_eq("the id", read(fd, &puid, 8), 8);
    if (puid < 1) {
        printf("goldfishpipe: process id %llu\n", (unsigned long long)puid);
        failed = 1;
    }
    want_eq("no second id", read(fd, &puid, 8), 0);

    // opengles: the name, the client flags and a call in one write.
    int gl = pipe_open(NULL);
    char one[14 + 4 + 8];
    memcpy(one, "pipe:opengles", 14);
    memset(one + 14, 0, 4);
    uint32_t version_call[2] = {10000, 8};
    memcpy(one + 18, version_call, 8);
    want_eq("name, flags and a call", write(gl, one, sizeof one), sizeof one);
    struct pollfd p = {.fd = gl, .events = POLLIN | POLLOUT};
    want_eq("poll with an answer waiting", poll(&p, 1, 0), 1);
    want_eq("POLLIN and POLLOUT", p.revents, POLLIN | POLLOUT);
    int32_t ret = 0;
    read_all(gl, &ret, 4);
    want_eq("rcGetRendererVersion", ret, 1);
    uint32_t outs[2] = {4, 4};
    call(gl, 10001, outs, 2);
    int32_t egl[3] = {0};
    read_all(gl, egl, 12);
    want_eq("rcGetEGLVersion's answer", egl[2], 1);
    if (egl[0] < 1) {
        printf("goldfishpipe: EGL %d.%d\n", egl[0], egl[1]);
        failed = 1;
    }
    uint32_t width = 1;
    call(gl, 10007, &width, 1);
    read_all(gl, &ret, 4);
    if (ret <= 0) {
        printf("goldfishpipe: display width %d\n", ret);
        failed = 1;
    }
    p.revents = 0;
    want_eq("poll with no answer", poll(&p, 1, 0), 1);
    want_eq("POLLOUT alone", p.revents, POLLOUT);
    fcntl(gl, F_SETFL, O_NONBLOCK);
    want("a non-blocking read with none", read(gl, b, 4), EAGAIN);
    fcntl(gl, F_SETFL, 0);

    // A color buffer, and its reference.
    uint32_t cb_params[3] = {16, 16, 0x1908};
    call(gl, 10012, cb_params, 3);
    uint32_t cb = 0;
    read_all(gl, &cb, 4);
    if (cb == 0) {
        printf("goldfishpipe: no color buffer\n");
        failed = 1;
    }
    int rc = pipe_open("refcount");
    want_eq("the handle", write(rc, &cb, 4), 4);
    want("read a refcount pipe", read(rc, b, 4), EIO);
    close(rc);
    close(gl);
    close(fd);
    umount(sys);
    umount(base);
    rmdir(base);
    if (!failed) {
        printf("goldfishpipe ok\n");
    }
    return failed;
}
