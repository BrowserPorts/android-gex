// AArch64's tagged pointers, as bionic uses them for its heap.
//
// The hardware ignores the top byte of a data address (Top Byte Ignore,
// Documentation/arch/arm64/tagged-pointers.rst), and a thread that has
// asked with PR_SET_TAGGED_ADDR_CTRL may pass a tagged pointer to a system
// call (Documentation/arch/arm64/tagged-address-abi.rst). bionic asks at
// start and, when the kernel agrees, tags what malloc returns with 0xb4.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_GET_TAGGED_ADDR_CTRL 56
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#endif

#define CHECK(c)                                          \
    do {                                                  \
        if (!(c)) {                                       \
            printf("%s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                     \
        }                                                 \
    } while (0)

static unsigned tag_of(const void *p) { return (unsigned)((uintptr_t)p >> 56); }

int main(void) {
    // The arguments an option does not take are zero, and without memory
    // tagging the enable bit is the only one.
    errno = 0;
    CHECK(prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 1, 0, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(prctl(PR_GET_TAGGED_ADDR_CTRL, 1, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0);
    CHECK(prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0) == (int)PR_TAGGED_ADDR_ENABLE);

    // bionic's heap pointers carry its tag, and are used like any other.
    size_t n = 64 * 1024;
    char *p = malloc(n), *q = malloc(n);
    CHECK(p && q);
    CHECK(tag_of(p) == 0xb4 && tag_of(q) == 0xb4);
    for (size_t i = 0; i < n; i++) p[i] = (char)(i * 31);
    memset(q, 0, n);

    // The kernel takes them: a pipe's worth out of one and into the other.
    int fds[2];
    CHECK(pipe(fds) == 0);
    CHECK(write(fds[1], p, 4096) == 4096);
    CHECK(read(fds[0], q, 4096) == 4096);
    CHECK(memcmp(p, q, 4096) == 0);

    // The byte is ignored whatever it holds, for memory of any kind.
    char *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED && tag_of(m) == 0);
    char *t = (char *)((uintptr_t)m | (0x5aULL << 56));
    t[17] = 'x';
    CHECK(m[17] == 'x');
    char local = 0;
    char *tl = (char *)((uintptr_t)&local | (0xffULL << 56));
    *tl = 'y';
    CHECK(local == 'y');
    CHECK(write(fds[1], t + 17, 1) == 1);
    CHECK(read(fds[0], tl, 1) == 1 && local == 'x');

    free(p);
    free(q);
    printf("tagged ok\n");
    return 0;
}
