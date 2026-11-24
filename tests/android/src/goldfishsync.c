// The emulator's goldfish sync device (goldfish_drivers/goldfish_sync.c at
// android17-6.18, misc 10:258 here), as the emulator image's composer uses
// it each frame: a host fence sync made over the pipe (rcCreateSyncKHR,
// destroyed when signalled), then QUEUE_WORK with its handles gives a
// close-on-exec sync file whose fence is the timeline's next point
// (driver sw_sync, timeline goldfish_sync:<n>) and signals once the host's
// sync has; no sync thread handle is EFAULT; another request ENOTTY.
//
// No Linux has this device without the emulator behind it, so the expected
// answers are the sources'. Run as root (mknod) with GEX_EMULATOR_HOST=1.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sync_file.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct queue_work {
    uint64_t glsync, syncthread;
    int32_t fence_fd;
};
#define QUEUE_WORK _IOWR('@', 0, struct queue_work)

static int failed;

static void want(const char *what, long r, int err) {
    int got = r >= 0 ? 0 : errno;
    if (got != err) {
        printf("goldfishsync: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

static void want_eq(const char *what, long long got, long long expect) {
    if (got != expect) {
        printf("goldfishsync: %s: want %lld, got %lld\n", what, expect, got);
        failed = 1;
    }
}

int main(void) {
    char base[] = "/tmp/goldfishsync-XXXXXX", sync_node[80], pipe_node[80];
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("goldfishsync: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(sync_node, sizeof sync_node, "%s/goldfish_sync", base);
    snprintf(pipe_node, sizeof pipe_node, "%s/goldfish_pipe_dprctd", base);
    if (mknod(sync_node, S_IFCHR | 0666, makedev(10, 258)) || mknod(pipe_node, S_IFCHR | 0666, makedev(10, 256))) {
        printf("goldfishsync: mknod (errno %d)\n", errno);
        return 1;
    }

    // rcCreateSyncKHR(EGL_SYNC_NATIVE_FENCE_ANDROID, attribs, 8, true,
    // &sync, &thread): the composer's, with no context current.
    int gl = open(pipe_node, O_RDWR);
    char hello[18];
    memcpy(hello, "pipe:opengles", 14);
    memset(hello + 14, 0, 4);
    want_eq("opengles", write(gl, hello, sizeof hello), sizeof hello);
    uint32_t create[] = {10029, 0, 0x3144, 8, 0x3144, (uint32_t)-1, 8, 1, 8, 8};
    create[1] = sizeof create;
    want_eq("rcCreateSyncKHR", write(gl, create, sizeof create), sizeof create);
    uint64_t handles[2] = {0, 0};
    want_eq("its handles", read(gl, handles, 16), 16);
    if (!handles[0] || !handles[1]) {
        printf("goldfishsync: no sync (%llu, %llu)\n", (unsigned long long)handles[0], (unsigned long long)handles[1]);
        return 1;
    }

    int fd = open(sync_node, O_RDWR);
    struct queue_work w = {.glsync = handles[0], .syncthread = 0, .fence_fd = -1};
    want("no sync thread", ioctl(fd, QUEUE_WORK, &w), EFAULT);
    want("another request", ioctl(fd, _IOWR('@', 1, struct queue_work), &w), ENOTTY);
    w.syncthread = handles[1];
    want("queue work", ioctl(fd, QUEUE_WORK, &w), 0);
    if (w.fence_fd < 0) {
        printf("goldfishsync: no fence\n");
        return 1;
    }
    want_eq("close-on-exec", fcntl(w.fence_fd, F_GETFD) & FD_CLOEXEC, FD_CLOEXEC);
    struct pollfd p = {.fd = w.fence_fd, .events = POLLIN};
    want_eq("signalled", poll(&p, 1, 1000), 1);
    struct sync_fence_info fi;
    struct sync_file_info info = {.num_fences = 1, .sync_fence_info = (uintptr_t)&fi};
    want("its info", ioctl(w.fence_fd, SYNC_IOC_FILE_INFO, &info), 0);
    want_eq("status", info.status, 1);
    if (strcmp(fi.driver_name, "sw_sync") || strncmp(fi.obj_name, "goldfish_sync:", 14)) {
        printf("goldfishsync: fence '%s' on '%s'\n", fi.driver_name, fi.obj_name);
        failed = 1;
    }
    // rcDestroySyncKHR, as the composer does after.
    uint32_t destroy[] = {10032, 16, 0, 0};
    memcpy(&destroy[2], &handles[0], 8);
    want_eq("rcDestroySyncKHR", write(gl, destroy, sizeof destroy), sizeof destroy);
    int32_t ret = -1;
    want_eq("its answer", read(gl, &ret, 4), 4);
    want_eq("rcDestroySyncKHR's answer", ret, 0);
    close(w.fence_fd);
    close(fd);
    close(gl);
    umount(base);
    rmdir(base);
    if (!failed) {
        printf("goldfishsync ok\n");
    }
    return failed;
}
