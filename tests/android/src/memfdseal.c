// memfd seals against mappings (mm/memfd.c, mm/shmem.c), as the zygote
// met them: a mapping made before F_SEAL_FUTURE_WRITE stays writable, and
// writing it back (msync, munmap) is not a write() the seal stops;
// F_SEAL_WRITE is EBUSY while a writable shared mapping exists, and fine
// once it is gone; a new writable shared mapping of a sealed memfd is
// EPERM, a read-only one or a private one is not, and the read-only one
// may not be made writable; write() is EPERM. A read-only shared mapping
// of an unsealed memfd may become writable, so it too keeps F_SEAL_WRITE
// off.
// Prints each answer and checks them against Linux 7.0's.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "future write seal: 0\n"
    "msync of the old mapping: 0\n"
    "the file has 1 2 3\n"
    "munmap of the old mapping: 0\n"
    "write(): -1\n"
    "a new writable shared mapping: -1\n"
    "a read-only one: 0, and made writable -13\n"
    "a private writable one: 0\n"
    "write seal with a writable mapping: -16\n"
    "seals now: 0\n"
    "munmap: 0\n"
    "write seal with a read-only mapping only: -16\n"
    "seals now: 0\n"
    "a writable shared mapping: 0; write() 1\n";

static char out_buf[4096];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[256];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    fflush(stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static int r(int v) {
    return v < 0 ? -errno : v;
}

static int mapped(void *p) {
    return p == MAP_FAILED ? -errno : 0;
}

int main(void) {
    int fd = memfd_create("future", MFD_ALLOW_SEALING);
    ftruncate(fd, 8192);
    char *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    p[0] = 1;
    SAY("future write seal: %d\n", r(fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE)));
    p[1] = 2;
    p[4096] = 3;
    SAY("msync of the old mapping: %d\n", r(msync(p, 8192, MS_SYNC)));
    char b[2] = {0}, c = 0;
    pread(fd, b, 2, 0);
    pread(fd, &c, 1, 4096);
    SAY("the file has %d %d %d\n", b[0], b[1], c);
    SAY("munmap of the old mapping: %d\n", r(munmap(p, 8192)));
    SAY("write(): %d\n", r((int)pwrite(fd, "x", 1, 0)));
    SAY("a new writable shared mapping: %d\n", mapped(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)));
    void *ro = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    SAY("a read-only one: %d, and made writable %d\n", mapped(ro), ro == MAP_FAILED ? 0 : r(mprotect(ro, 4096, PROT_READ | PROT_WRITE)));
    SAY("a private writable one: %d\n", mapped(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)));

    int fd2 = memfd_create("write", MFD_ALLOW_SEALING);
    ftruncate(fd2, 4096);
    char *q = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    q[0] = 5;
    SAY("write seal with a writable mapping: %d\n", r(fcntl(fd2, F_ADD_SEALS, F_SEAL_WRITE)));
    SAY("seals now: %x\n", r(fcntl(fd2, F_GET_SEALS)));
    SAY("munmap: %d\n", r(munmap(q, 4096)));
    void *ro2 = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd2, 0);
    SAY("write seal with a read-only mapping only: %d\n", r(fcntl(fd2, F_ADD_SEALS, F_SEAL_WRITE)));
    SAY("seals now: %x\n", r(fcntl(fd2, F_GET_SEALS)));
    SAY("a writable shared mapping: %d; write() %d\n", mapped(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0)), r((int)pwrite(fd2, "x", 1, 0)));
    munmap(ro2, 4096);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("memfdseal: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "memfdseal ok\n" : "memfdseal done\n");
    return 0;
}
