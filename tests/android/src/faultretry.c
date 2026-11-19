// An access with writeback that faults, and is made again once its
// handler has fixed the fault, as ART's compacting collector's threads do
// all the time (a userfaultfd page missing, SIGBUS, UFFDIO_COPY, return):
// the base register moves once, by the instruction's offset, and the
// access lands where it was aimed. A pre-indexed access that wrote its base
// before it was checked moved it twice, and read or wrote the wrong place.
// Loads and stores, single and pair, pre- and post-indexed; checked
// against Linux 7.0. And a fault in a loop the translator keeps in
// registers across its iterations: the handler's frame has every
// register as the instruction before the fault left it.
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#define P 4096
static int uffd;
static char *area;
static unsigned char page[P];
static volatile int faults;
static volatile uint64_t frame_x8;
static void bus(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    frame_x8 = ((ucontext_t *)uc)->uc_mcontext.regs[8];
    struct uffdio_copy c = {.dst = (uintptr_t)si->si_addr & ~(uintptr_t)(P - 1), .src = (uintptr_t)page, .len = P};
    ioctl(uffd, UFFDIO_COPY, &c);
    faults++;
}
// What Linux 7.0 printed.
static const char expected[] =
    "ldr pre-index: value right, base moved by 200 (faults 1)\n"
    "ldp pre-index: values right, base moved by 200 (faults 1)\n"
    "str pre-index: stored at right, base moved by 200 (faults 1)\n"
    "stp pre-index: stored at right, base moved by 200 (faults 1)\n"
    "ldr post-index from the missing page: value right, base moved by 8 (faults 1)\n"
    "str post-index into the missing page: stored right, base moved by 8 (faults 1)\n"
    "ldrb pre-index: value right, base moved by 200 (faults 1)\n"
    "byte loop into the missing page: right, the frame's base at the fault 2 (faults 1)\n";
static char out_buf[2048];
static size_t used;
#include <stdarg.h>
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
static void prep(void) { madvise(area, 4 * P, MADV_DONTNEED); volatile char x = area[0]; (void)x; faults = 0; }
#define V(o) (*(uint64_t *)(page + (o)))
int main(void) {
    for (int i = 0; i < P; i++) page[i] = (unsigned char)(0x41 + i % 23);
    uffd = syscall(SYS_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
    struct uffdio_api api = {.api = UFFD_API, .features = UFFD_FEATURE_SIGBUS};
    ioctl(uffd, UFFDIO_API, &api);
    area = mmap(0, 4 * P, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct uffdio_register reg = {.range = {(uintptr_t)area, 4 * P}, .mode = UFFDIO_REGISTER_MODE_MISSING};
    ioctl(uffd, UFFDIO_REGISTER, &reg);
    struct sigaction sa = {0};
    sa.sa_sigaction = bus;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, 0);
    char *base = area + 4000;
    uint64_t a, b, x;
    prep();
    __asm__ volatile("mov x9, %2\n ldr %0, [x9, #200]!\n mov %1, x9" : "=&r"(a), "=&r"(x) : "r"(base) : "x9", "memory");
    SAY("ldr pre-index: value %s, base moved by %ld (faults %d)\n", a == V(104) ? "right" : "wrong", (long)(x - (uint64_t)base), faults);
    prep();
    __asm__ volatile("mov x9, %3\n ldp %0, %1, [x9, #200]!\n mov %2, x9" : "=&r"(a), "=&r"(b), "=&r"(x) : "r"(base) : "x9", "memory");
    SAY("ldp pre-index: values %s, base moved by %ld (faults %d)\n", a == V(104) && b == V(112) ? "right" : "wrong", (long)(x - (uint64_t)base), faults);
    prep();
    __asm__ volatile("mov x9, %1\n mov x10, #77\n str x10, [x9, #200]!\n mov %0, x9" : "=&r"(x) : "r"(base) : "x9", "x10", "memory");
    SAY("str pre-index: stored at %s, base moved by %ld (faults %d)\n", *(uint64_t *)(area + 4200) == 77 ? "right" : "wrong", (long)(x - (uint64_t)base), faults);
    prep();
    __asm__ volatile("mov x9, %1\n mov x10, #66\n stp x10, x10, [x9, #200]!\n mov %0, x9" : "=&r"(x) : "r"(base) : "x9", "x10", "memory");
    SAY("stp pre-index: stored at %s, base moved by %ld (faults %d)\n", *(uint64_t *)(area + 4208) == 66 && *(uint64_t *)(area + 4200) == 66 ? "right" : "wrong", (long)(x - (uint64_t)base), faults);
    prep();
    __asm__ volatile("mov x9, %2\n ldr %0, [x9], #8\n mov %1, x9" : "=&r"(a), "=&r"(x) : "r"(area + 4200) : "x9", "memory");
    SAY("ldr post-index from the missing page: value %s, base moved by %ld (faults %d)\n", a == V(104) ? "right" : "wrong", (long)(x - (uint64_t)(area + 4200)), faults);
    prep();
    __asm__ volatile("mov x9, %1\n mov x10, #55\n str x10, [x9], #8\n mov %0, x9" : "=&r"(x) : "r"(area + 4200) : "x9", "x10", "memory");
    SAY("str post-index into the missing page: stored %s, base moved by %ld (faults %d)\n", *(uint64_t *)(area + 4200) == 55 ? "right" : "wrong", (long)(x - (uint64_t)(area + 4200)), faults);
    prep();
    __asm__ volatile("mov x9, %2\n ldrb %w0, [x9, #200]!\n mov %1, x9" : "=&r"(a), "=&r"(x) : "r"(base) : "x9", "memory");
    SAY("ldrb pre-index: value %s, base moved by %ld (faults %d)\n", a == page[104] ? "right" : "wrong", (long)(x - (uint64_t)base), faults);
    // A loop that copies a byte at a time, each store post-indexed: the
    // store that faults is retried where it was aimed, and the handler's
    // frame has the base as the previous iteration left it.
    {
        static const unsigned char src[8] = "ABCD";
        prep();
        unsigned char *d = (unsigned char *)area + P - 2;
        __asm__ volatile(
            "mov x8, %0\n mov x1, %1\n mov x2, #4\n"
            "1: ldrb w9, [x1], #1\n subs x2, x2, #1\n strb w9, [x8], #1\n b.ne 1b\n"
            :: "r"(d), "r"(src) : "x1", "x2", "x8", "x9", "memory", "cc");
        SAY("byte loop into the missing page: %s, the frame's base at the fault %ld (faults %d)\n", !memcmp(d, src, 4) ? "right" : "wrong", (long)((unsigned char *)frame_x8 - d), faults);
    }
    if (strcmp(out_buf, expected) != 0) {
        printf("faultretry: not what Linux shows\n");
        return 1;
    }
    printf("faultretry ok\n");
    return 0;
}
