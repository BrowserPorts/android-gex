// A process's resident size is the pages it has touched, not what it has
// mapped: a large anonymous mapping adds nothing to VmRSS until written,
// and then what was written. /proc/self/status and statm agree. Prints
// yes or no for each; Linux 7.0 says yes to all.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static long status_rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "VmRSS: %ld kB", &kb) == 1)
            break;
    if (f)
        fclose(f);
    return kb;
}

static long statm_rss_kb(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    long size = 0, res = -1;
    if (f && fscanf(f, "%ld %ld", &size, &res) != 2)
        res = -1;
    if (f)
        fclose(f);
    return res * 4;
}

static int bad;

static const char *yes(int c) {
    bad |= !c;
    return c ? "yes" : "no";
}

int main(void) {
    const size_t map = 256u << 20, touch = 64u << 20;
    long r0 = status_rss_kb();
    char *p = mmap(NULL, map, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return 2;
    long r1 = status_rss_kb();
    printf("mapped 256 MiB, VmRSS grew under 4 MiB: %s\n", yes(r1 - r0 < 4096));
    for (size_t i = 0; i < touch; i += 4096)
        p[i] = 1;
    long r2 = status_rss_kb(), s2 = statm_rss_kb();
    printf("touched 64 MiB, VmRSS grew 60 to 72 MiB: %s\n", yes(r2 - r1 >= 60 * 1024 && r2 - r1 <= 72 * 1024));
    printf("statm agrees within 4 MiB: %s\n", yes(s2 - r2 < 4096 && r2 - s2 < 4096));
    munmap(p, map);
    long r3 = status_rss_kb();
    printf("unmapped, VmRSS fell back within 4 MiB: %s\n", yes(r3 - r0 < 4096));
    printf(bad ? "rss: not as Linux counts it\n" : "rss ok\n");
    return bad;
}
