// DMA-BUF heaps (drivers/dma-buf/dma-heap.c, heaps/system_heap.c), which
// Android's graphics allocator takes its buffers from: a heap's node is
// found as ueventd finds it (sysfs, the class dma_heap, the node under
// dma_heap/); an allocation is a dma-buf of the length rounded up to
// pages, its descriptor as the flags say, mapped as its access allows,
// one memory however many times mapped; the checks of the argument; the
// command known by its number alone. A kernel with no system heap passes
// with a note. Run as root (mknod, mount).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
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

static int failed;

static void want(const char *what, long r, int err) {
    int got = r >= 0 ? 0 : errno;
    if (got != err) {
        printf("dmaheap: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

static void is(const char *what, long got, long expect) {
    if (got != expect) {
        printf("dmaheap: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static char sys[64], base[] = "/tmp/dmaheap-XXXXXX";

static int text(const char *path, char *buf, int len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, len - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    return n;
}

// A heap's node, made from its number in sysfs; -1 if it is not there.
static int heap(const char *name) {
    char path[160], dev[32], node[96];
    snprintf(path, sizeof path, "%s/class/dma_heap/%s/dev", sys, name);
    if (text(path, dev, sizeof dev) <= 0) return -1;
    unsigned ma, mi;
    if (sscanf(dev, "%u:%u", &ma, &mi) != 2) return -1;
    snprintf(node, sizeof node, "%s/%s", base, name);
    if (mknod(node, S_IFCHR | 0444, makedev(ma, mi))) return -1;
    return open(node, O_RDONLY | O_CLOEXEC);
}

static long alloc(int h, uint64_t len, uint32_t fd_flags, uint64_t heap_flags, uint32_t fd) {
    struct dma_heap_allocation_data d = {.len = len, .fd = fd, .fd_flags = fd_flags, .heap_flags = heap_flags};
    if (ioctl(h, DMA_HEAP_IOCTL_ALLOC, &d)) return -1;
    return d.fd;
}

int main(void) {
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("dmaheap: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(sys, sizeof sys, "%s/sys", base);
    if (mkdir(sys, 0755) || mount("sysfs", sys, "sysfs", 0, NULL)) {
        printf("dmaheap: sysfs (errno %d)\n", errno);
        return 1;
    }
    int h = heap("system");
    if (h < 0) {
        printf("dmaheap: no system heap here\n");
    } else {
        char path[160], ev[160], want_ev[160], dev[32];
        snprintf(path, sizeof path, "%s/class/dma_heap/system/uevent", sys);
        text(path, ev, sizeof ev);
        snprintf(path, sizeof path, "%s/class/dma_heap/system/dev", sys);
        text(path, dev, sizeof dev);
        unsigned ma, mi;
        sscanf(dev, "%u:%u", &ma, &mi);
        snprintf(want_ev, sizeof want_ev, "MAJOR=%u\nMINOR=%u\nDEVNAME=dma_heap/system\n", ma, mi);
        if (strcmp(ev, want_ev)) {
            printf("dmaheap: uevent \"%s\"\n", ev);
            failed = 1;
        }
        // The heap itself: no read, no seek.
        char c;
        want("a read of the heap", read(h, &c, 1), EINVAL);
        want("a seek of the heap", lseek(h, 0, SEEK_SET), ESPIPE);

        // One byte is a page.
        long b = alloc(h, 1, O_RDWR | O_CLOEXEC, 0, 0);
        want("an allocation", b, 0);
        struct stat st;
        is("its size", fstat(b, &st) ? -1 : st.st_size, 4096);
        is("its end", lseek(b, 0, SEEK_END), 4096);
        is("close on exec", fcntl(b, F_GETFD) & FD_CLOEXEC, FD_CLOEXEC);
        is("read and write", fcntl(b, F_GETFL) & O_ACCMODE, O_RDWR);
        struct dma_buf_sync sync = {.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW};
        want("sync start", ioctl(b, DMA_BUF_IOCTL_SYNC, &sync), 0);
        unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, b, 0);
        unsigned char *q = mmap(NULL, 4096, PROT_READ, MAP_SHARED, b, 0);
        if (p == MAP_FAILED || q == MAP_FAILED) {
            printf("dmaheap: mmap (errno %d)\n", errno);
            return 1;
        }
        is("zeroed", p[0] | p[4095], 0);
        memcpy(p + 100, "heap", 4);
        sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW;
        want("sync end", ioctl(b, DMA_BUF_IOCTL_SYNC, &sync), 0);
        is("one memory", !memcmp(q + 100, "heap", 4), 1);
        munmap(p, 4096);
        munmap(q, 4096);
        want("a mapping past the end", mmap(NULL, 8192, PROT_READ, MAP_SHARED, b, 0) == MAP_FAILED ? -1 : 0, EINVAL);
        close(b);

        // Read-only: no writable mapping; no close on exec unless asked.
        long r = alloc(h, 5000, O_RDONLY, 0, 0);
        want("a read-only allocation", r, 0);
        is("its size, rounded", lseek(r, 0, SEEK_END), 8192);
        is("not close on exec", fcntl(r, F_GETFD) & FD_CLOEXEC, 0);
        want("a writable mapping of it", mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, r, 0) == MAP_FAILED ? -1 : 0, EACCES);
        close(r);

        // The argument's checks.
        want("a descriptor given", alloc(h, 4096, O_RDWR, 0, 3), EINVAL);
        want("O_NONBLOCK", alloc(h, 4096, O_RDWR | O_NONBLOCK, 0, 0), EINVAL);
        want("a heap flag", alloc(h, 4096, O_RDWR, 1, 0), EINVAL);
        want("no length", alloc(h, 0, O_RDWR, 0, 0), EINVAL);
        want("a length that wraps", alloc(h, (uint64_t)-1, O_RDWR, 0, 0), EINVAL);

        // The command by its number: another magic is the same command; a
        // shorter argument is zeroed past what was given; a number past
        // the last is EINVAL.
        struct dma_heap_allocation_data d = {.len = 4096, .fd_flags = O_RDWR};
        want("another magic", ioctl(h, _IOWR('X', 0, struct dma_heap_allocation_data), &d), 0);
        if (d.fd > 0) close(d.fd);
        struct { uint64_t len; uint32_t fd, fd_flags; } short_arg = {4096, 0, O_RDWR};
        want("a shorter argument", ioctl(h, _IOWR('H', 0, short_arg), &short_arg), 0);
        if (short_arg.fd > 0) close(short_arg.fd);
        is("its descriptor", short_arg.fd > 0, 1);
        want("number 1", ioctl(h, _IOWR('H', 1, struct dma_heap_allocation_data), &d), EINVAL);
        close(h);

        // The uncached heap, where the system heap has one (Android's).
        int u = heap("system-uncached");
        if (u >= 0) {
            long ub = alloc(u, 4096, O_RDWR, 0, 0);
            want("an uncached allocation", ub, 0);
            if (ub >= 0) close(ub);
            close(u);
        }
    }
    umount2(sys, MNT_DETACH);
    umount2(base, MNT_DETACH);
    rmdir(base);
    if (failed) return 1;
    printf("dmaheap ok\n");
    return 0;
}
