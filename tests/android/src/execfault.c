// A branch to an address that cannot be run is the fault the processor
// takes there, with the context's pc the address itself: SIGSEGV with
// SEGV_MAPERR where nothing is mapped (a null function pointer), and with
// SEGV_ACCERR where the page is mapped but may not be run, whether it is
// branched to or run into from the page before it. An address that is no
// multiple of four is SIGBUS with BUS_ADRALN, and the context's
// fault_address is then 0.
//
// The frame's esr_context is an instruction abort's (class 0x20): a
// permission fault for a page that is there, a translation fault where
// nothing is or the page allows nothing; or a PC alignment fault's (0x22).
//
// The handler sees the registers as the branch left them: the link
// register holds where the call would have returned to, and a handler that
// puts it in pc returns from the call.
#define _GNU_SOURCE
#include <asm/sigcontext.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

static sigjmp_buf out;
static volatile int faults, sig, code, back;
static volatile uintptr_t at, pc, in_context;
static volatile uint64_t esr;

static void on_fault(int s, siginfo_t *si, void *ctx) {
    ucontext_t *uc = ctx;
    faults++;
    sig = s;
    code = si->si_code;
    at = (uintptr_t)si->si_addr;
    pc = uc->uc_mcontext.pc;
    in_context = uc->uc_mcontext.fault_address;
    esr = 0;
    for (struct _aarch64_ctx *r = (void *)uc->uc_mcontext.__reserved; r->magic; r = (void *)((char *)r + r->size))
        if (r->magic == ESR_MAGIC) esr = ((struct esr_context *)r)->esr;
    if (back) {
        // Return from the call that went nowhere.
        uc->uc_mcontext.pc = uc->uc_mcontext.regs[30];
        return;
    }
    siglongjmp(out, 1);
}

typedef void (*fn)(void);

__attribute__((noinline)) static void call(fn f) {
    faults = 0;
    if (!sigsetjmp(out, 1)) f();
}

static int fail(const char *what) {
    printf("execfault: %s: %d faults, signal %d code %d at %#lx, pc %#lx, context %#lx, esr %#lx\n", what, faults, sig, code, (unsigned long)at,
           (unsigned long)pc, (unsigned long)in_context, (unsigned long)esr);
    return 1;
}

// One SIGSEGV with this code at `where`, the pc there too, and an
// instruction abort's syndrome of this kind (its status less the level: 1 a
// translation fault, 3 a permission fault).
static int segv(int want, uintptr_t where, int kind) {
    return faults == 1 && sig == SIGSEGV && code == want && at == where && pc == where && in_context == where && esr >> 26 == 0x20 &&
           (int)(esr >> 2 & 15) == kind;
}

int main(void) {
    struct sigaction sa = {.sa_sigaction = on_fault, .sa_flags = SA_SIGINFO};
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    size_t pg = (size_t)getpagesize();

    // Two pages of `ret`.
    uint32_t *a = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (a == MAP_FAILED) return 2;
    for (size_t i = 0; i < 2 * pg / 4; i++) a[i] = 0xd65f03c0;
    uintptr_t A = (uintptr_t)a;

    call((fn)0);
    if (!segv(SEGV_MAPERR, 0, 1)) return fail("a null function pointer");
    call((fn)16);
    if (!segv(SEGV_MAPERR, 16, 1)) return fail("a branch to page zero");

    // Mapped, and written, but not to be run.
    call((fn)A);
    if (!segv(SEGV_ACCERR, A, 3)) return fail("a branch to a page that may not be run");
    mprotect(a, pg, PROT_NONE);
    call((fn)A);
    if (!segv(SEGV_ACCERR, A, 1)) return fail("a branch to a page with no access");

    // To be run: it returns.
    mprotect(a, pg, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)a, (char *)a + pg);
    call((fn)A);
    if (faults) return fail("a branch to a page that may be run");

    // Its last two instructions made `nop`: the code runs on into the
    // second page, which may not be run.
    mprotect(a, pg, PROT_READ | PROT_WRITE);
    a[pg / 4 - 2] = a[pg / 4 - 1] = 0xd503201f;
    mprotect(a, pg, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)a, (char *)a + pg);
    call((fn)(A + pg - 8));
    if (!segv(SEGV_ACCERR, A + pg, 3)) return fail("code that runs on into a page that may not be run");

    // An address off its four bytes, in the page that may be run.
    call((fn)(A + 2));
    if (faults != 1 || sig != SIGBUS || code != BUS_ADRALN || at != A + 2 || pc != A + 2 || in_context != 0 || esr != 0x8a000000)
        return fail("a branch to an address that is no multiple of four");

    // The handler returns from a call that went nowhere.
    munmap(a, 2 * pg);
    faults = 0;
    back = 1;
    ((fn)A)();
    back = 0;
    if (!segv(SEGV_MAPERR, A, 1)) return fail("a call the handler returned from");

    printf("execfault ok\n");
    return 0;
}
