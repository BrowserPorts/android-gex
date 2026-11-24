// madvise(MADV_DONTNEED) on anonymous private memory, as ART's collector
// and the allocators use it: the range reads as zero after, bytes either
// side of it (in the same page or not) are kept, and the memory is given
// back, so the process's resident size (VmRSS) falls by about the range.
// A write after it works and reads back. A start that is not page-aligned
// is EINVAL. A shared anonymous mapping keeps its contents (its pages come
// back from the shared memory behind it, as a shared file mapping's from
// the file). Prints nothing when all is as Linux has it.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("dontneed: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

// VmRSS, in KiB.
static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f)) {
        if (!strncmp(line, "VmRSS:", 6)) kb = strtol(line + 6, NULL, 10);
    }
    if (f) fclose(f);
    return kb;
}

static int all(const unsigned char *p, size_t n, unsigned char v) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

int main(void) {
    const size_t len = 64 << 20;
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("dontneed: mmap: %d\n", errno);
        return 1;
    }
    memset(p, 0x5a, len);
    long before = rss_kb();
    // A page in from either end: not on a 16 KiB host page's boundary, so
    // a host with larger pages zeroes the edges itself.
    size_t lo = 4096, hi = len - 4096;
    want("madvise", madvise(p + lo, hi - lo, MADV_DONTNEED), 0);
    // Measured before the range is read: reading it may give the process
    // pages of zeros again (Linux maps its zero page, which is not counted).
    long after = rss_kb();
    want("the range reads zero", all(p + lo, hi - lo, 0), 1);
    want("before it is kept", all(p, lo, 0x5a), 1);
    want("after it is kept", all(p + hi, len - hi, 0x5a), 1);
    // At least 48 of the 64 MiB given back (the host's pages may be larger).
    want("the memory is given back", before - after >= (48 << 10), 1);
    p[lo + 12345] = 7;
    want("a write after", p[lo + 12345], 7);
    want("its neighbours", p[lo + 12344] == 0 && p[lo + 12346] == 0, 1);
    // Unaligned: madvise wants a page-aligned start.
    want("an unaligned start", madvise(p + 1, 4096, MADV_DONTNEED) == 0 ? 0 : -errno, -EINVAL);
    munmap(p, len);

    // A shared anonymous mapping: its contents come back.
    unsigned char *s = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(s, 0x33, 1 << 20);
    want("madvise shared", madvise(s, 1 << 20, MADV_DONTNEED), 0);
    want("shared keeps its contents", all(s, 1 << 20, 0x33), 1);
    munmap(s, 1 << 20);
    if (!failed) printf("dontneed ok\n");
    return failed;
}
