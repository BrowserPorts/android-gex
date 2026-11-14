// A signal's frame carries the FP and vector state, an fpsimd_context
// record at the start of the context's __reserved: the handler reads the
// interrupted code's registers there, what it writes there is what the code
// goes on with, and whatever the handler itself does to the registers is
// undone when it returns.
//
// A fault's frame has an esr_context record after that one: the syndrome
// of a data abort from the program (class 0x24), write-not-read for a
// store. It is a permission fault for a store to a page that is there to
// read, and a translation fault where nothing is mapped or the page allows
// nothing (which the processor has no entry for either).
#define _GNU_SOURCE
#include <asm/sigcontext.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static struct _aarch64_ctx *record(ucontext_t *uc, uint32_t magic) {
    struct _aarch64_ctx *h = (void *)uc->uc_mcontext.__reserved;
    while (h->magic) {
        if (h->magic == magic) return h;
        h = (void *)((char *)h + h->size);
    }
    return 0;
}

static volatile int usr1_ok;
static volatile uint64_t esr;
static volatile int has_esr;
static sigjmp_buf out;

#define NEW_V1_LO 0x5555666677778888ULL
#define NEW_V1_HI 0x1111222233334444ULL

static void on_usr1(int sig, siginfo_t *si, void *ctx) {
    ucontext_t *uc = ctx;
    (void)sig;
    (void)si;
    struct fpsimd_context *fp = (void *)record(uc, FPSIMD_MAGIC);
    int ok = fp && (char *)fp == (char *)uc->uc_mcontext.__reserved && fp->head.size == sizeof *fp;
    if (ok) {
        // v0 is {0, 1}, v31 {62, 63}: the doublewords main loaded.
        ok = (uint64_t)fp->vregs[0] == 0x1000 && (uint64_t)(fp->vregs[0] >> 64) == 0x1001 && (uint64_t)fp->vregs[31] == 0x1000 + 62 &&
             (uint64_t)(fp->vregs[31] >> 64) == 0x1000 + 63;
        ok = ok && !record(uc, ESR_MAGIC);
        fp->vregs[1] = (__uint128_t)NEW_V1_HI << 64 | NEW_V1_LO;
    }
    usr1_ok = ok;
    // The handler's own use of them all.
    __asm__ volatile("movi v0.16b, #0xff\n movi v1.16b, #0xff\n movi v2.16b, #0xff\n movi v3.16b, #0xff\n"
                     "movi v4.16b, #0xff\n movi v5.16b, #0xff\n movi v6.16b, #0xff\n movi v7.16b, #0xff\n"
                     "movi v8.16b, #0xff\n movi v9.16b, #0xff\n movi v10.16b, #0xff\n movi v11.16b, #0xff\n"
                     "movi v12.16b, #0xff\n movi v13.16b, #0xff\n movi v14.16b, #0xff\n movi v15.16b, #0xff\n"
                     "movi v16.16b, #0xff\n movi v17.16b, #0xff\n movi v18.16b, #0xff\n movi v19.16b, #0xff\n"
                     "movi v20.16b, #0xff\n movi v21.16b, #0xff\n movi v22.16b, #0xff\n movi v23.16b, #0xff\n"
                     "movi v24.16b, #0xff\n movi v25.16b, #0xff\n movi v26.16b, #0xff\n movi v27.16b, #0xff\n"
                     "movi v28.16b, #0xff\n movi v29.16b, #0xff\n movi v30.16b, #0xff\n movi v31.16b, #0xff"
                     :
                     :
                     : "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19",
                       "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
}

static void on_segv(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    (void)si;
    struct esr_context *e = (void *)record(ctx, ESR_MAGIC);
    has_esr = e && e->head.size == sizeof *e && record(ctx, FPSIMD_MAGIC) && (void *)e > (void *)record(ctx, FPSIMD_MAGIC);
    esr = e ? e->esr : 0;
    siglongjmp(out, 1);
}

// Loads every vector register from `in`, sends this thread `sig` (the
// handler runs before the call returns), and stores them all to `got`.
__attribute__((noinline)) static void around_signal(const uint64_t *in, uint64_t *got, long pid, long tid, long sig) {
    register long x0 __asm__("x0") = pid;
    register long x1 __asm__("x1") = tid;
    register long x2 __asm__("x2") = sig;
    register long x8 __asm__("x8") = SYS_tgkill;
    __asm__ volatile("ldp q0, q1, [%[in]]\n ldp q2, q3, [%[in], #32]\n ldp q4, q5, [%[in], #64]\n ldp q6, q7, [%[in], #96]\n"
                     "ldp q8, q9, [%[in], #128]\n ldp q10, q11, [%[in], #160]\n ldp q12, q13, [%[in], #192]\n ldp q14, q15, [%[in], #224]\n"
                     "ldp q16, q17, [%[in], #256]\n ldp q18, q19, [%[in], #288]\n ldp q20, q21, [%[in], #320]\n ldp q22, q23, [%[in], #352]\n"
                     "ldp q24, q25, [%[in], #384]\n ldp q26, q27, [%[in], #416]\n ldp q28, q29, [%[in], #448]\n ldp q30, q31, [%[in], #480]\n"
                     "svc #0\n"
                     "stp q0, q1, [%[got]]\n stp q2, q3, [%[got], #32]\n stp q4, q5, [%[got], #64]\n stp q6, q7, [%[got], #96]\n"
                     "stp q8, q9, [%[got], #128]\n stp q10, q11, [%[got], #160]\n stp q12, q13, [%[got], #192]\n stp q14, q15, [%[got], #224]\n"
                     "stp q16, q17, [%[got], #256]\n stp q18, q19, [%[got], #288]\n stp q20, q21, [%[got], #320]\n stp q22, q23, [%[got], #352]\n"
                     "stp q24, q25, [%[got], #384]\n stp q26, q27, [%[got], #416]\n stp q28, q29, [%[got], #448]\n stp q30, q31, [%[got], #480]"
                     : "+r"(x0)
                     : [in] "r"(in), [got] "r"(got), "r"(x1), "r"(x2), "r"(x8)
                     : "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17",
                       "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
}

// The syndrome of a fault doing `store` at `p`, or 0 with no record.
static uint64_t syndrome(volatile uint8_t *p, int store) {
    has_esr = 0;
    esr = 0;
    if (!sigsetjmp(out, 1)) {
        if (store)
            *p = 1;
        else
            (void)*p;
    }
    return has_esr ? esr : 0;
}

int main(void) {
    int status = 0;
    struct sigaction sa = {.sa_sigaction = on_usr1, .sa_flags = SA_SIGINFO};
    sigaction(SIGUSR1, &sa, 0);
    sa.sa_sigaction = on_segv;
    sigaction(SIGSEGV, &sa, 0);

    uint64_t in[64], got[64];
    for (int i = 0; i < 64; i++) in[i] = 0x1000 + i;
    memset(got, 0, sizeof got);
    around_signal(in, got, getpid(), gettid(), SIGUSR1);
    if (!usr1_ok) status |= 1;
    for (int i = 0; i < 64; i++) {
        uint64_t want = i == 2 ? NEW_V1_LO : i == 3 ? NEW_V1_HI : in[i];
        if (got[i] != want) status |= 2;
    }

    size_t pg = (size_t)getpagesize();
    uint8_t *a = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    munmap(a + pg, pg);
    // Written first, so that the page is there when it is made read-only.
    a[0] = 1;
    mprotect(a, pg, PROT_READ);
    uint64_t e[4] = {syndrome(a + pg, 0), syndrome(a + pg, 1), syndrome(a, 1), 0};
    mprotect(a, pg, PROT_NONE);
    e[3] = syndrome(a, 0);
    // Class, write-not-read, and the kind of fault (the status code less
    // its level): 1 a translation fault, 3 a permission fault.
    int want[4][2] = {{0, 1}, {1, 1}, {1, 3}, {0, 1}};
    for (int i = 0; i < 4; i++) {
        if (e[i] >> 26 != 0x24 || (int)(e[i] >> 6 & 1) != want[i][0] || (int)(e[i] >> 2 & 15) != want[i][1]) {
            printf("sigframe: syndrome %d is %#lx\n", i, (unsigned long)e[i]);
            status |= 8;
        }
    }

    if (status) {
        printf("sigframe %d\n", status);
        return 1;
    }
    printf("sigframe ok\n");
    return 0;
}
