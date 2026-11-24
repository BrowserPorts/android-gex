// The emulator's goldfish address space (goldfish_drivers/
// goldfish_address_space.c at android17-6.18, misc 10:257 here), as the
// emulator image's graphics allocator uses it (Mesa's
// goldfish_address_space.cpp, hostMalloc with no shared slots), and the
// mapper's DMA calls that reach a buffer's memory by its physical address:
//
// - the first ping names the open's host context (the host memory
//   allocator, 5: metadata 0 back); a block is allocated (its size whole
//   pages, its physical address the area's base plus its offset); the host
//   allocates it (metadata 0, and -1 a second time); it maps shared;
// - a mapping outside the open's blocks, or another open's, is EPERM; a
//   block another open does not have cannot be given back by it (ENXIO);
// - pixels written in the mapping reach a color buffer by
//   rcUpdateColorBufferDMA at the block's physical address, and come back
//   into the mapping by rcReadColorBufferDMA at another one.
//
// No Linux has this device without the emulator behind it, so the expected
// answers are the sources'. Run as root (mknod) with GEX_EMULATOR_HOST=1.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

struct allocate_block {
    uint64_t size, offset, phys_addr;
};
struct ping {
    uint64_t offset, size, metadata;
    uint32_t version, wait_fd, wait_flags, direction;
};
#define AS_ALLOCATE _IOWR('G', 10, struct allocate_block)
#define AS_DEALLOCATE _IOWR('G', 11, uint64_t)
#define AS_PING _IOWR('G', 12, struct ping)

static int failed;

static void want(const char *what, long r, int err) {
    int got = r >= 0 ? 0 : errno;
    if (got != err) {
        printf("goldfishas: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

static void want_eq(const char *what, long long got, long long expect) {
    if (got != expect) {
        printf("goldfishas: %s: want %lld, got %lld\n", what, expect, got);
        failed = 1;
    }
}

static uint64_t ping(int fd, uint64_t offset, uint64_t size, uint64_t metadata) {
    struct ping p = {.offset = offset, .size = size, .metadata = metadata};
    want("ping", ioctl(fd, AS_PING, &p), 0);
    return p.metadata;
}

// A renderControl call on the pipe, and its 4-byte answer.
static int32_t call(int gl, const void *words, size_t len) {
    want_eq("a call's write", write(gl, words, len), (long long)len);
    int32_t ret = 0;
    want_eq("its answer", read(gl, &ret, 4), 4);
    return ret;
}

int main(void) {
    char base[] = "/tmp/goldfishas-XXXXXX", as_node[80], pipe_node[80];
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("goldfishas: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(as_node, sizeof as_node, "%s/goldfish_address_space", base);
    snprintf(pipe_node, sizeof pipe_node, "%s/goldfish_pipe_dprctd", base);
    if (mknod(as_node, S_IFCHR | 0666, makedev(10, 257)) || mknod(pipe_node, S_IFCHR | 0666, makedev(10, 256))) {
        printf("goldfishas: mknod (errno %d)\n", errno);
        return 1;
    }

    // hostMalloc.
    int fd = open(as_node, O_RDWR);
    if (fd < 0) {
        printf("goldfishas: open: %s\n", strerror(errno));
        return 1;
    }
    want_eq("the host memory allocator", ping(fd, 0, 0, 5), 0);
    struct allocate_block b = {.size = 5000};
    want("allocate", ioctl(fd, AS_ALLOCATE, &b), 0);
    want_eq("whole pages", b.size, 8192);
    want_eq("its physical address", b.phys_addr - b.offset, 0x4000000000LL);
    want_eq("host memory", ping(fd, b.offset, b.size, 1), 0);
    want_eq("host memory again", (int64_t)ping(fd, b.offset, b.size, 1), -1);
    unsigned char *p = mmap(NULL, b.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, b.offset);
    if (p == MAP_FAILED) {
        printf("goldfishas: mmap: %s\n", strerror(errno));
        return 1;
    }
    want("past the block", (long)mmap(NULL, 8192, PROT_READ, MAP_SHARED, fd, b.offset + 4096), EPERM);
    int other = open(as_node, O_RDWR);
    want("another open's block", (long)mmap(NULL, 4096, PROT_READ, MAP_SHARED, other, b.offset), EPERM);
    uint64_t off = b.offset;
    want("give back another's", ioctl(other, AS_DEALLOCATE, &off), ENXIO);
    close(other);

    // The mapper's path: a 4x4 RGBA color buffer, written from the block
    // and read back into it a page further on.
    for (int i = 0; i < 64; i++) {
        p[i] = (unsigned char)(i * 3);
    }
    int gl = open(pipe_node, O_RDWR);
    char hello[18];
    memcpy(hello, "pipe:opengles", 14);
    memset(hello + 14, 0, 4);
    want_eq("opengles", write(gl, hello, sizeof hello), sizeof hello);
    uint32_t create[6] = {10035, 24, 4, 4, 0x1908, 0};
    int32_t cb = call(gl, create, sizeof create);
    if (cb == 0) {
        printf("goldfishas: no color buffer\n");
        return 1;
    }
    // opcode, length, color buffer, x, y, w, h, format, type, the address
    // (8 bytes), the size.
    uint32_t dma[12] = {0, 48, (uint32_t)cb, 0, 0, 4, 4, 0x1908, 0x1401, 0, 0, 64};
    dma[0] = 10034;
    memcpy(&dma[9], &b.phys_addr, 8);
    want_eq("rcUpdateColorBufferDMA", call(gl, dma, sizeof dma), 0);
    dma[0] = 10064;
    uint64_t back = b.phys_addr + 4096;
    memcpy(&dma[9], &back, 8);
    want_eq("rcReadColorBufferDMA", call(gl, dma, sizeof dma), 0);
    if (memcmp(p, p + 4096, 64)) {
        printf("goldfishas: the pixels read back differ (%d %d %d, want %d %d %d)\n", p[4096], p[4097], p[4098], p[0], p[1], p[2]);
        failed = 1;
    }
    close(gl);
    munmap(p, b.size);
    want("give it back", ioctl(fd, AS_DEALLOCATE, &off), 0);
    want("give it back twice", ioctl(fd, AS_DEALLOCATE, &off), ENXIO);
    close(fd);
    umount(base);
    rmdir(base);
    if (!failed) {
        printf("goldfishas ok\n");
    }
    return failed;
}
