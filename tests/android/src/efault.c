// A system call is held to the program's own pages: where it would read
// what the program may not read, or write what it may not write, it fails
// with EFAULT and does nothing, whether nothing is mapped there, the page
// allows no access, or it may only be read and the call would write it. A
// string that runs off the end of what may be read is EFAULT too. A call
// that touches no byte (a length of zero) does not look.
//
// The calls are made by number, so that none is answered from the vDSO,
// which would fault instead.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static int failures;

// The call fails with EFAULT.
#define EFAULTS(what, call)                                                        \
    do {                                                                           \
        errno = 0;                                                                 \
        long r_ = (long)(call);                                                    \
        if (r_ != -1 || errno != EFAULT) {                                         \
            printf("efault: %s: %ld, errno %d (wanted EFAULT)\n", what, r_, errno); \
            failures++;                                                            \
        }                                                                          \
    } while (0)

// The call returns `want`.
#define GIVES(what, call, want)                                                \
    do {                                                                       \
        errno = 0;                                                             \
        long r_ = (long)(call);                                                \
        if (r_ != (long)(want)) {                                              \
            printf("efault: %s: %ld, errno %d (wanted %ld)\n", what, r_, errno, (long)(want)); \
            failures++;                                                        \
        }                                                                      \
    } while (0)

int main(void) {
    size_t pg = (size_t)getpagesize();
    // Four pages: read-write, read-only, no access, and one unmapped again.
    char *a = mmap(0, 4 * pg, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (a == MAP_FAILED) return 2;
    memset(a, 'x', 3 * pg);
    char *rw = a, *ro = a + pg, *none = a + 2 * pg, *gone = a + 3 * pg;
    mprotect(ro, pg, PROT_READ);
    mprotect(none, pg, PROT_NONE);
    munmap(gone, pg);

    int p[2];
    if (pipe(p)) return 2;
    // Enough in the pipe for every read below.
    GIVES("a write from a page that may be read", write(p[1], ro, 64), 64);

    // Reads: the call would write the buffer.
    EFAULTS("a read into nothing", read(p[0], gone, 8));
    EFAULTS("a read into a page with no access", read(p[0], none, 8));
    EFAULTS("a read into a read-only page", read(p[0], ro, 8));
    EFAULTS("a read into a null pointer", read(p[0], 0, 8));
    EFAULTS("a read into page zero", read(p[0], (void *)64, 8));
    GIVES("a read of no bytes into nothing", read(p[0], gone, 0), 0);
    GIVES("a read into a page that may be written", read(p[0], rw, 8), 8);
    // Nothing was taken from the pipe by the calls that failed.
    GIVES("the bytes still in the pipe", read(p[0], rw, 4096), 56);

    // Writes: the call would read the buffer.
    EFAULTS("a write from nothing", write(p[1], gone, 8));
    EFAULTS("a write from a page with no access", write(p[1], none, 8));
    EFAULTS("a write from a null pointer", write(p[1], 0, 8));
    GIVES("a write of no bytes from nothing", write(p[1], gone, 0), 0);
    // A page that may only be written may be read.
    mprotect(rw, pg, PROT_WRITE);
    GIVES("a write from a write-only page", write(p[1], rw, 8), 8);
    mprotect(rw, pg, PROT_READ | PROT_WRITE);
    GIVES("draining the pipe", read(p[0], rw, 4096), 8);

    // A gathered read whose second buffer may not be written.
    struct iovec iov[2] = {{rw, 4}, {ro, 4}};
    GIVES("a write for the gathered read", write(p[1], "12345678", 8), 8);
    errno = 0;
    long got = readv(p[0], iov, 2);
    if (!(got == 4 || (got == -1 && errno == EFAULT))) {
        printf("efault: a gathered read into a read-only page: %ld, errno %d\n", got, errno);
        failures++;
    }
    EFAULTS("a gathered read whose vector is nothing", readv(p[0], (struct iovec *)gone, 1));

    // Strings: a path that is nothing, and one with no end before the
    // page it may not read.
    EFAULTS("opening a path at nothing", openat(AT_FDCWD, gone, O_RDONLY));
    EFAULTS("opening a null path", openat(AT_FDCWD, 0, O_RDONLY));
    mprotect(ro, pg, PROT_READ | PROT_WRITE);
    memset(ro, 'p', pg);
    mprotect(ro, pg, PROT_READ);
    EFAULTS("opening a path that runs into a page with no access", openat(AT_FDCWD, ro + pg - 16, O_RDONLY));
    GIVES("opening a path that ends in time", openat(AT_FDCWD, "/definitely/not/there", O_RDONLY), -1);
    if (errno != ENOENT) failures++;

    // Structures the call fills in.
    struct stat st;
    GIVES("stat into a page that may be written", fstatat(p[0], "", &st, AT_EMPTY_PATH), 0);
    EFAULTS("stat into a read-only page", fstatat(p[0], "", (struct stat *)ro, AT_EMPTY_PATH));
    EFAULTS("stat into nothing", fstatat(p[0], "", (struct stat *)gone, AT_EMPTY_PATH));
    EFAULTS("uname into a read-only page", syscall(SYS_uname, ro));
    EFAULTS("the time into a read-only page", syscall(SYS_clock_gettime, CLOCK_MONOTONIC, ro));
    EFAULTS("the time into nothing", syscall(SYS_clock_gettime, CLOCK_MONOTONIC, gone));
    EFAULTS("a pipe's descriptors into a read-only page", syscall(SYS_pipe2, ro, 0));
    EFAULTS("the working directory into a read-only page", syscall(SYS_getcwd, ro, 256));
    EFAULTS("random bytes into nothing", syscall(SYS_getrandom, gone, 16, 0));

    // Structures the call reads.
    EFAULTS("a sleep whose time is nothing", syscall(SYS_nanosleep, gone, 0));
    EFAULTS("a signal action that is nothing", syscall(SYS_rt_sigaction, SIGUSR1, gone, 0, 8));
    EFAULTS("a futex word that is nothing", syscall(SYS_futex, gone, FUTEX_WAIT, 0, 0, 0, 0));
    EFAULTS("a futex word in a page with no access", syscall(SYS_futex, none, FUTEX_WAIT, 0, 0, 0, 0));

    if (failures) {
        printf("efault %d\n", failures);
        return 1;
    }
    printf("efault ok\n");
    return 0;
}
