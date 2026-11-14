// mremap to an address the caller fixes: the pages move over whatever was
// there, with their protection, and the old range is gone; longer, the
// rest is zero; shorter, the tail is dropped. MREMAP_DONTUNMAP leaves the
// old range mapped and empty. The flags are checked as the kernel checks
// them. bionic's loader publishes its control-flow shadow a page at a time
// this way, a read-only page moved over a reserved one.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#define CHECK(c)                                          \
    do {                                                  \
        if (!(c)) {                                       \
            printf("%s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                     \
        }                                                 \
    } while (0)

enum { P = 4096 };
static const int rw = PROT_READ | PROT_WRITE, anon = MAP_PRIVATE | MAP_ANONYMOUS;

static int gone(void *p) {
    return msync(p, P, MS_ASYNC) == -1 && errno == ENOMEM;
}

int main(void) {
    char *src = mmap(0, 2 * P, rw, anon, -1, 0);
    char *dst = mmap(0, 8 * P, PROT_NONE, anon, -1, 0);
    CHECK(src != MAP_FAILED && dst != MAP_FAILED);
    memset(src, 'a', P);
    memset(src + P, 'b', P);

    // What is refused, and nothing moved by it.
    CHECK(mremap(src, 2 * P, 2 * P, MREMAP_FIXED, dst) == MAP_FAILED && errno == EINVAL);
    CHECK(mremap(src, 2 * P, 2 * P, 8, dst) == MAP_FAILED && errno == EINVAL);
    CHECK(mremap(src, 2 * P, 2 * P, MREMAP_MAYMOVE | MREMAP_FIXED, dst + 1) == MAP_FAILED && errno == EINVAL);
    CHECK(mremap(src, 2 * P, 2 * P, MREMAP_MAYMOVE | MREMAP_FIXED, src + P) == MAP_FAILED && errno == EINVAL);
    CHECK(mremap(src, P, 2 * P, MREMAP_MAYMOVE | MREMAP_DONTUNMAP) == MAP_FAILED && errno == EINVAL);
    CHECK(mremap(src, P, P, MREMAP_DONTUNMAP) == MAP_FAILED && errno == EINVAL);
    CHECK(src[0] == 'a' && src[P] == 'b');

    // Moved into the middle of the reservation, protection and all.
    CHECK(mremap(src, 2 * P, 2 * P, MREMAP_MAYMOVE | MREMAP_FIXED, dst + P) == dst + P);
    CHECK(dst[P] == 'a' && dst[2 * P] == 'b' && dst[3 * P - 1] == 'b');
    dst[P] = 'c';
    CHECK(gone(src) && gone(src + P));
    CHECK(mprotect(dst, P, PROT_READ) == 0 && dst[0] == 0);

    // Longer at the new place: the rest is zero. Shorter: only that much.
    CHECK(mremap(dst + P, P, 3 * P, MREMAP_MAYMOVE | MREMAP_FIXED, dst + 4 * P) == dst + 4 * P);
    CHECK(dst[4 * P] == 'c' && dst[4 * P + 1] == 'a' && dst[5 * P] == 0 && dst[7 * P - 1] == 0);
    CHECK(gone(dst + P) && dst[2 * P] == 'b');
    dst[6 * P] = 'z';
    char *small = mmap(0, P, PROT_NONE, anon, -1, 0);
    CHECK(small != MAP_FAILED);
    CHECK(mremap(dst + 4 * P, 3 * P, P, MREMAP_MAYMOVE | MREMAP_FIXED, small) == small);
    CHECK(small[0] == 'c' && gone(dst + 4 * P) && gone(dst + 6 * P));

    // The loader's way: a page written, made read-only, moved over a
    // reserved one.
    char *tmp = mmap(0, P, rw, anon, -1, 0);
    CHECK(tmp != MAP_FAILED);
    memset(tmp, 's', P);
    CHECK(mprotect(tmp, P, PROT_READ) == 0);
    CHECK(mremap(tmp, P, P, MREMAP_MAYMOVE | MREMAP_FIXED, dst + 7 * P) == dst + 7 * P);
    CHECK(dst[7 * P] == 's' && dst[8 * P - 1] == 's' && gone(tmp));

    // The source kept: mapped still, and empty.
    char *kept = mmap(0, P, rw, anon, -1, 0);
    CHECK(kept != MAP_FAILED);
    kept[5] = 'k';
    char *moved = mremap(kept, P, P, MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
    CHECK(moved != MAP_FAILED && moved != kept && moved[5] == 'k');
    CHECK(kept[5] == 0);
    kept[5] = 'n';
    CHECK(moved[5] == 'k');

    printf("mremap ok\n");
    return 0;
}
