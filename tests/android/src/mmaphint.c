// A mapping's address hint, as ART uses it for its boot image (at
// 0x70000000 and up) and its heap (0x12c00000): with the range free, Linux
// places the mapping at the hint, without MAP_FIXED; with it taken, it
// places it elsewhere; MAP_FIXED_NOREPLACE is the hint or EEXIST. Prints
// whether each landed at its hint; checks against Linux 7.0's answers.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// What Linux 7.0 printed.
static const char expected[] =
    "boot image's address, 64 MiB: at the hint\n"
    "boot image's address, 256 MiB: at the hint\n"
    "boot image's address, 768 MiB: at the hint\n"
    "heap's address, 512 MiB: at the hint\n"
    "an unaligned hint: elsewhere\n"
    "at 16 GiB, 1 MiB: at the hint\n"
    "a file at the boot image's address: at the hint\n"
    "a file there with noreplace: at the hint\n"
    "noreplace on a free range: at the hint\n"
    "a hint on that taken range: elsewhere\n"
    "noreplace on it: EEXIST\n"
    "noreplace overlapping it: EEXIST\n";

static char out_buf[2048];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[256];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static void *try_map(uintptr_t at, size_t len, int flags) {
    return mmap((void *)at, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
}

static void hint(const char *what, uintptr_t at, size_t len) {
    void *p = try_map(at, len, 0);
    SAY("%s: %s\n", what, p == MAP_FAILED ? "failed" : p == (void *)at ? "at the hint" : "elsewhere");
    if (p != MAP_FAILED)
        munmap(p, len);
}

int main(void) {
    hint("boot image's address, 64 MiB", 0x70000000, 64 << 20);
    hint("boot image's address, 256 MiB", 0x700e8000, 256 << 20);
    hint("boot image's address, 768 MiB", 0x70000000, 768u << 20);
    hint("heap's address, 512 MiB", 0x12c00000, 512 << 20);
    hint("an unaligned hint", 0x70000123, 1 << 20);
    hint("at 16 GiB, 1 MiB", 0x400000000ull, 1 << 20);

    // A file's mapping, as ART maps an image file.
    char path[] = "/tmp/gex-mmaphint-XXXXXX";
    int fd = mkstemp(path);
    unlink(path);
    if (fd < 0 || ftruncate(fd, 8 << 20) != 0)
        return 2;
    void *f = mmap((void *)0x70100000, 8 << 20, PROT_READ, MAP_PRIVATE, fd, 0);
    SAY("a file at the boot image's address: %s\n", f == MAP_FAILED ? "failed" : f == (void *)0x70100000 ? "at the hint" : "elsewhere");
    if (f != MAP_FAILED)
        munmap(f, 8 << 20);
    void *g = mmap((void *)0x70100000, 8 << 20, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    SAY("a file there with noreplace: %s\n", g == MAP_FAILED ? "failed" : g == (void *)0x70100000 ? "at the hint" : "elsewhere");
    if (g != MAP_FAILED)
        munmap(g, 8 << 20);
    close(fd);

    // Taken: elsewhere without a flag, EEXIST with MAP_FIXED_NOREPLACE.
    void *a = try_map(0x71000000, 1 << 20, MAP_FIXED_NOREPLACE);
    SAY("noreplace on a free range: %s\n", a == (void *)0x71000000 ? "at the hint" : "not");
    void *b = try_map(0x71000000, 1 << 20, 0);
    SAY("a hint on that taken range: %s\n", b == MAP_FAILED ? "failed" : b == (void *)0x71000000 ? "at the hint" : "elsewhere");
    void *c = try_map(0x71000000, 1 << 20, MAP_FIXED_NOREPLACE);
    SAY("noreplace on it: %s\n", c == MAP_FAILED ? (errno == EEXIST ? "EEXIST" : "another error") : "mapped");
    void *d = try_map(0x70f80000, 1 << 20, MAP_FIXED_NOREPLACE);
    SAY("noreplace overlapping it: %s\n", d == MAP_FAILED ? (errno == EEXIST ? "EEXIST" : "another error") : "mapped");

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("mmaphint: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "mmaphint ok\n" : "mmaphint done\n");
    return 0;
}
