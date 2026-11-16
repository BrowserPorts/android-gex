// userfaultfd as ART's concurrent compacting collector uses it
// (art/runtime/gc/collector/mark_compact.cc): faults taken as SIGBUS. A
// range is registered (missing mode) and then emptied, by MADV_DONTNEED or
// by an mremap that leaves the source behind (MREMAP_DONTUNMAP); a thread
// that touches an empty page of it takes SIGBUS (BUS_ADRERR, at the
// address), its handler fills the page (UFFDIO_COPY, UFFDIO_ZEROPAGE) and
// returns, and the access is made again.
//
// - UFFDIO_API: once, offering UFFD_FEATURE_SIGBUS; a wrong api, or a
//   second call, EINVAL; nothing else before it;
// - UFFDIO_REGISTER: mode 0 or a range with nothing mapped EINVAL; the
//   range's ioctls include COPY and ZEROPAGE;
// - a touch of an emptied page is SIGBUS to its handler, in whichever
//   thread touches it; one not emptied is read as it was;
// - UFFDIO_COPY of a filled page is EEXIST (and says so in its count),
//   outside the registered range ENOENT;
// - a system call that writes into an emptied page is EFAULT;
// - unregistered, or the descriptor closed, an emptied page reads as zero;
// - without CAP_SYS_PTRACE, only UFFD_USER_MODE_ONLY (EPERM otherwise).
//
// As root (for the last).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

static long page;
static int uffd = -1;
static char *area, *src, *area2;
static volatile int faults;
static void *volatile last_addr;
static volatile int last_code;

static void fail(const char *what, long got, long want) {
    printf("uffd: %s: got %ld (errno %d), wanted %ld\n", what, got, errno, want);
    exit(1);
}

static void expect(const char *what, long got, long want) {
    if (got != want) fail(what, got, want);
}

static long R(long r) {
    return r < 0 ? -errno : r;
}

// What ART's handler does: fill the page the fault was at, and return.
static void on_bus(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    faults++;
    last_addr = si->si_addr;
    last_code = si->si_code;
    uintptr_t p = (uintptr_t)si->si_addr & ~(uintptr_t)(page - 1);
    if (p >= (uintptr_t)area && p < (uintptr_t)area + 4 * page) {
        struct uffdio_copy c = {.dst = p, .src = (uintptr_t)src + (p - (uintptr_t)area), .len = page, .mode = 0};
        if (ioctl(uffd, UFFDIO_COPY, &c) && errno != EEXIST) _exit(90);
    } else {
        struct uffdio_zeropage z = {.range = {.start = p, .len = page}, .mode = 0};
        if (ioctl(uffd, UFFDIO_ZEROPAGE, &z) && errno != EEXIST) _exit(91);
    }
}

static void *toucher(void *arg) {
    return (void *)(intptr_t)*(volatile char *)arg;
}

static int make(int flags) {
    return (int)syscall(__NR_userfaultfd, flags);
}

int main(void) {
    page = sysconf(_SC_PAGESIZE);

    // UFFDIO_API.
    int fd = make(O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
    if (fd < 0) fail("userfaultfd", -errno, 0);
    struct uffdio_api api = {.api = 0x55, .features = 0};
    expect("UFFDIO_API with a wrong api", R(ioctl(fd, UFFDIO_API, &api)), -EINVAL);
    expect("the struct zeroed after", (long)(api.api | api.features | api.ioctls), 0);
    api = (struct uffdio_api){.api = UFFD_API, .features = 0};
    expect("UFFDIO_API", R(ioctl(fd, UFFDIO_API, &api)), 0);
    expect("UFFD_FEATURE_SIGBUS offered", !!(api.features & UFFD_FEATURE_SIGBUS), 1);
    expect("its ioctls", (long)(api.ioctls & (1ULL << _UFFDIO_REGISTER | 1ULL << _UFFDIO_UNREGISTER | 1ULL << _UFFDIO_API)), (long)(1ULL << _UFFDIO_REGISTER | 1ULL << _UFFDIO_UNREGISTER | 1ULL << _UFFDIO_API));
    api = (struct uffdio_api){.api = UFFD_API, .features = 0};
    expect("UFFDIO_API again", R(ioctl(fd, UFFDIO_API, &api)), -EINVAL);
    close(fd);

    uffd = make(O_CLOEXEC | UFFD_USER_MODE_ONLY);
    if (uffd < 0) fail("userfaultfd", -errno, 0);
    area = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    src = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (area == MAP_FAILED || src == MAP_FAILED) fail("mmap", -errno, 0);
    for (int i = 0; i < 4; i++) {
        memset(area + i * page, 'a' + i, page);
        memset(src + i * page, 'A' + i, page);
    }
    struct uffdio_register reg = {.range = {.start = (uintptr_t)area, .len = 4 * page}, .mode = UFFDIO_REGISTER_MODE_MISSING};
    expect("UFFDIO_REGISTER before UFFDIO_API", R(ioctl(uffd, UFFDIO_REGISTER, &reg)), -EINVAL);
    api = (struct uffdio_api){.api = UFFD_API, .features = UFFD_FEATURE_SIGBUS};
    expect("UFFDIO_API asking for SIGBUS", R(ioctl(uffd, UFFDIO_API, &api)), 0);

    // UFFDIO_REGISTER.
    reg.mode = 0;
    expect("UFFDIO_REGISTER mode 0", R(ioctl(uffd, UFFDIO_REGISTER, &reg)), -EINVAL);
    char *hole = mmap(NULL, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(hole, page);
    struct uffdio_register none = {.range = {.start = (uintptr_t)hole, .len = page}, .mode = UFFDIO_REGISTER_MODE_MISSING};
    expect("UFFDIO_REGISTER where nothing is mapped", R(ioctl(uffd, UFFDIO_REGISTER, &none)), -EINVAL);
    reg.mode = UFFDIO_REGISTER_MODE_MISSING;
    expect("UFFDIO_REGISTER", R(ioctl(uffd, UFFDIO_REGISTER, &reg)), 0);
    expect("COPY and ZEROPAGE on the range", (long)(reg.ioctls & (1ULL << _UFFDIO_COPY | 1ULL << _UFFDIO_ZEROPAGE)), (long)(1ULL << _UFFDIO_COPY | 1ULL << _UFFDIO_ZEROPAGE));

    struct sigaction sa = {0};
    sa.sa_sigaction = on_bus;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL);

    // Not emptied: as it was.
    expect("a page not emptied", *(volatile char *)area, 'a');
    expect("no fault", faults, 0);

    // Emptied: SIGBUS, filled by the handler.
    if (madvise(area, 4 * page, MADV_DONTNEED)) fail("madvise", -errno, 0);
    expect("an emptied page, filled", *(volatile char *)(area + page + 7), 'B');
    expect("one fault", faults, 1);
    expect("at the address", (long)((char *)last_addr - area), page + 7);
    expect("BUS_ADRERR", last_code, BUS_ADRERR);
    expect("written to, after", (area[page + 8] = 'z', area[page + 8]), 'z');
    expect("still one fault", faults, 1);

    // UFFDIO_ZEROPAGE, and UFFDIO_COPY of a filled page or outside.
    struct uffdio_zeropage z = {.range = {.start = (uintptr_t)area + 2 * page, .len = page}};
    expect("UFFDIO_ZEROPAGE", R(ioctl(uffd, UFFDIO_ZEROPAGE, &z)), 0);
    expect("its count", (long)z.zeropage, page);
    expect("the zeroed page", *(volatile char *)(area + 2 * page), 0);
    struct uffdio_copy c = {.dst = (uintptr_t)area + page, .src = (uintptr_t)src, .len = page};
    expect("UFFDIO_COPY of a filled page", R(ioctl(uffd, UFFDIO_COPY, &c)), -EEXIST);
    expect("its count", (long)c.copy, -EEXIST);
    c = (struct uffdio_copy){.dst = (uintptr_t)src, .src = (uintptr_t)area, .len = page};
    expect("UFFDIO_COPY outside the range", R(ioctl(uffd, UFFDIO_COPY, &c)), -ENOENT);
    expect("still one fault", faults, 1);

    // A system call writing into an emptied page.
    int pfd[2];
    if (pipe(pfd) || write(pfd[1], "xyz", 3) != 3) fail("pipe", -errno, 0);
    expect("read() into an emptied page", R(read(pfd[0], area + 3 * page, 3)), -EFAULT);
    expect("no fault for it", faults, 1);

    // Another thread's touch.
    pthread_t t;
    void *got = NULL;
    if (pthread_create(&t, NULL, toucher, area + 3 * page) || pthread_join(t, &got)) fail("a thread", -errno, 0);
    expect("the thread's read, filled", (long)(intptr_t)got, 'D');
    expect("two faults", faults, 2);

    // An mremap that leaves its source: the source's pages are empty.
    area2 = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(area2, 'x', 2 * page);
    struct uffdio_register reg2 = {.range = {.start = (uintptr_t)area2, .len = 2 * page}, .mode = UFFDIO_REGISTER_MODE_MISSING};
    expect("UFFDIO_REGISTER of the second", R(ioctl(uffd, UFFDIO_REGISTER, &reg2)), 0);
    char *moved = mremap(area2, 2 * page, 2 * page, MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
    if (moved == MAP_FAILED) fail("mremap", -errno, 0);
    expect("what moved", moved[page], 'x');
    expect("the source, filled with zero", *(volatile char *)area2, 0);
    expect("three faults", faults, 3);

    // Unregistered: an emptied page reads as zero.
    struct uffdio_range r = {.start = (uintptr_t)area, .len = 4 * page};
    expect("UFFDIO_UNREGISTER", R(ioctl(uffd, UFFDIO_UNREGISTER, &r)), 0);
    if (madvise(area, page, MADV_DONTNEED)) fail("madvise", -errno, 0);
    expect("an emptied page, unregistered", *(volatile char *)area, 0);
    expect("still three faults", faults, 3);

    // Closed: what it registered is not.
    close(uffd);
    expect("the second's other page, its descriptor closed", *(volatile char *)(area2 + page), 0);
    expect("still three faults", faults, 3);

    // Without CAP_SYS_PTRACE (vm.unprivileged_userfaultfd 0).
    pid_t child = fork();
    if (child == 0) {
        if (setgid(1000) || setuid(1000)) _exit(10);
        if (make(O_CLOEXEC) >= 0 || errno != EPERM) _exit(11);
        if (make(O_CLOEXEC | 0x4000) >= 0 || errno != EPERM) _exit(12);
        int ok = make(O_CLOEXEC | UFFD_USER_MODE_ONLY);
        if (ok < 0) _exit(13);
        if (make(UFFD_USER_MODE_ONLY | 0x4000) >= 0 || errno != EINVAL) _exit(14);
        _exit(0);
    }
    int status = -1;
    if (child < 0 || waitpid(child, &status, 0) != child) fail("the child", status, 0);
    expect("the child without CAP_SYS_PTRACE", status, 0);

    printf("uffd ok\n");
    return 0;
}
