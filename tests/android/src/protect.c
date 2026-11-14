// A program's own accesses are held to its pages' protections, as the
// processor holds them: a load or a store a page does not allow is SIGSEGV
// at the instruction, with the address in si_addr and in the context's
// fault_address, SEGV_MAPERR where nothing is mapped and SEGV_ACCERR where
// the protection refuses it. What a page allows is what it is mapped with
// now, after mprotect and munmap.
//
// The handler sees the state before the instruction: it can make the page
// writable and return, and the store then happens; or step over the
// instruction and set the register it would have loaded.
//
// A page that may be written may be read. An access that begins in a page
// that allows it and ends in one that does not faults in the second. A
// pointer's top byte is not part of the address reported. What the library
// does for the program faults as its own accesses would: memcpy and memset
// into a page they may not write, an atomic add, and a block zeroed by
// `dc zva`.
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_TAGGED_ADDR_ENABLE 1
#endif

static sigjmp_buf out;
static volatile int faults;
static volatile int code;
static volatile uintptr_t at, in_context, at_pc, x1_then;
// What the handler does: 0 leaves by siglongjmp; 1 makes `fix` writable and
// returns; 2 steps over the instruction, with 0x1234 in x0.
static volatile int mode;
static void *volatile fix;
static size_t pg;

static void on_segv(int sig, siginfo_t *si, void *ctx) {
    ucontext_t *uc = ctx;
    (void)sig;
    faults++;
    code = si->si_code;
    at = (uintptr_t)si->si_addr;
    in_context = uc->uc_mcontext.fault_address;
    at_pc = uc->uc_mcontext.pc;
    x1_then = uc->uc_mcontext.regs[1];
    if (mode == 1) {
        mprotect(fix, pg, PROT_READ | PROT_WRITE);
        return;
    }
    if (mode == 2) {
        uc->uc_mcontext.regs[0] = 0x1234;
        uc->uc_mcontext.pc += 4;
        return;
    }
    siglongjmp(out, 1);
}

__attribute__((noinline)) static uint64_t load8(const void *p) {
    uint64_t v;
    __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}

__attribute__((noinline)) static uint8_t load1(const void *p) {
    uint8_t v;
    __asm__ volatile("ldrb %w0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}

__attribute__((noinline)) static void store1(void *p, uint8_t v) {
    __asm__ volatile("strb %w0, [%1]" : : "r"(v), "r"(p) : "memory");
}

// One load at a label, for the handler that steps over it.
extern char the_load[];
__attribute__((noinline)) static uint64_t load_at_label(const void *p) {
    register uint64_t x0 __asm__("x0") = 7;
    register const void *x1 __asm__("x1") = p;
    __asm__ volatile(".globl the_load\nthe_load: ldr x0, [x1]" : "+r"(x0) : "r"(x1) : "memory");
    return x0;
}

static int fail(const char *what) {
    printf("protect: %s: %d faults, code %d, at %#lx (context %#lx), pc %#lx\n", what, faults, code, (unsigned long)at, (unsigned long)in_context,
           (unsigned long)at_pc);
    return 1;
}

// One fault, with this code, at this address, which the context has too.
static int was(int want_code, uintptr_t where) {
    return faults == 1 && code == want_code && at == where && in_context == where;
}

// One fault, with this code, somewhere in `[lo, hi)`.
static int within(int want_code, uintptr_t lo, uintptr_t hi) {
    return faults == 1 && code == want_code && at >= lo && at < hi && in_context == at;
}

#define TRY(stmt)                 \
    do {                          \
        faults = 0;               \
        mode = 0;                 \
        if (!sigsetjmp(out, 1)) { \
            stmt;                 \
        }                         \
    } while (0)

int main(void) {
    pg = (size_t)getpagesize();
    struct sigaction sa = {.sa_sigaction = on_segv, .sa_flags = SA_SIGINFO};
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);

    // Three pages; the third is unmapped again, so nothing follows the second.
    uint8_t *a = mmap(0, 3 * pg, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (a == MAP_FAILED) return 2;
    munmap(a + 2 * pg, pg);
    a[0] = 1;
    a[pg] = 2;
    uintptr_t A = (uintptr_t)a;

    // A store to a read-only page; a load of it is fine.
    mprotect(a, pg, PROT_READ);
    TRY(store1(a + 8, 9));
    if (!was(SEGV_ACCERR, A + 8) || a[8] != 0) return fail("a store to a read-only page");
    TRY((void)load1(a));
    if (faults) return fail("a load from a read-only page");

    // A load from a page with no access.
    mprotect(a, pg, PROT_NONE);
    TRY((void)load1(a + 5));
    if (!was(SEGV_ACCERR, A + 5)) return fail("a load from a page with no access");

    // Writable again: the store happens.
    mprotect(a, pg, PROT_READ | PROT_WRITE);
    TRY(store1(a + 8, 3));
    if (faults || a[8] != 3) return fail("a store to a page writable again");

    // A page that may only be written may be read.
    mprotect(a, pg, PROT_WRITE);
    TRY((void)load1(a));
    if (faults) return fail("a load from a write-only page");
    mprotect(a, pg, PROT_READ | PROT_WRITE);

    // Where nothing is mapped: the page after the second, and page zero.
    TRY((void)load1(a + 2 * pg + 1));
    if (!was(SEGV_MAPERR, A + 2 * pg + 1)) return fail("a load where nothing is mapped");
    TRY(store1((void *)16, 1));
    if (!was(SEGV_MAPERR, 16)) return fail("a store through a null pointer");
    TRY((void)load8((void *)0));
    if (!was(SEGV_MAPERR, 0)) return fail("a load of a null pointer");

    // Eight bytes from the last four of the second page: the fault is in
    // the page after it.
    TRY((void)load8(a + 2 * pg - 4));
    if (!was(SEGV_MAPERR, A + 2 * pg)) return fail("a load that runs into an unmapped page");
    // And from the last four of the first into a second with no access.
    mprotect(a + pg, pg, PROT_NONE);
    TRY((void)load8(a + pg - 4));
    if (!was(SEGV_ACCERR, A + pg)) return fail("a load that runs into a page with no access");
    mprotect(a + pg, pg, PROT_READ | PROT_WRITE);
    TRY((void)load8(a + pg - 4));
    if (faults) return fail("a load across two readable pages");

    // The handler makes the page writable and returns: the store happens.
    mprotect(a, pg, PROT_READ);
    faults = 0;
    mode = 1;
    fix = a;
    store1(a + 100, 77);
    mode = 0;
    if (!was(SEGV_ACCERR, A + 100) || a[100] != 77) return fail("a store the handler made room for");

    // The handler steps over the load, at the label, with x1 the address.
    faults = 0;
    mode = 2;
    uint64_t got = load_at_label(a + 2 * pg + 24);
    mode = 0;
    if (!was(SEGV_MAPERR, A + 2 * pg + 24) || got != 0x1234 || at_pc != (uintptr_t)the_load || x1_then != A + 2 * pg + 24) return fail("a load the handler stepped over");

    // A tagged pointer's fault is reported without its tag.
    if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0) {
        uint8_t *tagged = (uint8_t *)((uintptr_t)(a + 2 * pg + 40) | (uintptr_t)0x5a << 56);
        TRY((void)load1(tagged));
        if (!was(SEGV_MAPERR, A + 2 * pg + 40)) return fail("a load through a tagged pointer");
    }

    // The library's copies and fills: into the read-only first page from
    // the second, and from the second on into what follows it.
    static uint8_t block[256];
    mprotect(a, pg, PROT_READ);
    TRY(memcpy(a + 200, block, sizeof block));
    if (!within(SEGV_ACCERR, A + 200, A + 200 + sizeof block)) return fail("memcpy into a read-only page");
    TRY(memset(a + 300, 1, 128));
    if (!within(SEGV_ACCERR, A + 300, A + 300 + 128)) return fail("memset of a read-only page");
    TRY(memset(a + 2 * pg - 64, 1, 256));
    if (!within(SEGV_MAPERR, A + 2 * pg, A + 2 * pg + 192)) return fail("memset that runs into an unmapped page");
    TRY(memcpy(block, a + 2 * pg - 64, 256));
    if (!within(SEGV_MAPERR, A + 2 * pg, A + 2 * pg + 192)) return fail("memcpy that runs out of an unmapped page");
    TRY(memcpy(block, a + 2 * pg - 256, 256));
    if (faults) return fail("memcpy from the last bytes of a page");

    // An atomic add of a word in the read-only page.
    TRY(__atomic_fetch_add((uint32_t *)(a + 64), 1, __ATOMIC_SEQ_CST));
    if (!was(SEGV_ACCERR, A + 64)) return fail("an atomic add in a read-only page");

    // A block zeroed by `dc zva`, in the read-only page.
    TRY(__asm__ volatile("dc zva, %0" : : "r"(a + 512 + 8) : "memory"));
    if (!within(SEGV_ACCERR, A + 512, A + 512 + 64)) return fail("dc zva in a read-only page");

    // Unmapped altogether, the first page faults as nothing mapped.
    munmap(a, pg);
    TRY((void)load1(a));
    if (!was(SEGV_MAPERR, A)) return fail("a load from a page unmapped");

    printf("protect ok\n");
    return 0;
}
