// casp on an X pair and a W pair: an equal pair is replaced, an unequal one
// (either half) is left, and the first pair of registers always comes back
// holding what was in memory. x30's partner is the zero register. A pair
// off its sixteen-byte boundary is SIGBUS with BUS_ADRALN.
//
// Then four threads add to one sixteen-byte counter whose second half is
// kept at three times its first, two with casp and two with ldxp/stxp. A
// casp returns both halves from one instant, so every pair it reads back
// must hold that, and so must the total. One more thread loads the pair
// exclusively, waits while another changes only the second half, and must
// then fail its store: the first half alone does not tell the two apart.
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>

#define LSE __attribute__((target("lse"), noinline))

typedef struct {
    unsigned long lo, hi;
} pair;

static pair one __attribute__((aligned(16))) = {1, 2};
static unsigned int words[2] __attribute__((aligned(8))) = {7, 9};
static pair counter __attribute__((aligned(16)));
static pair watched __attribute__((aligned(16))) = {40, 1};
static volatile int stage;
static sigjmp_buf out;
static volatile int bus_code;

// casp: 1 when `*p` held `*want` and now holds `with`; `*want` gets what
// `*p` held either way.
LSE static int casp(pair *p, pair *want, pair with) {
    register unsigned long x0 __asm__("x0") = want->lo;
    register unsigned long x1 __asm__("x1") = want->hi;
    register unsigned long x2 __asm__("x2") = with.lo;
    register unsigned long x3 __asm__("x3") = with.hi;
    __asm__ volatile("caspal x0, x1, x2, x3, [%4]" : "+r"(x0), "+r"(x1) : "r"(x2), "r"(x3), "r"(p) : "memory");
    int swapped = x0 == want->lo && x1 == want->hi;
    want->lo = x0;
    want->hi = x1;
    return swapped;
}

LSE static int casp_w(unsigned int *p, unsigned int *want, unsigned int lo, unsigned int hi) {
    register unsigned int w0 __asm__("w0") = want[0];
    register unsigned int w1 __asm__("w1") = want[1];
    register unsigned int w2 __asm__("w2") = lo;
    register unsigned int w3 __asm__("w3") = hi;
    __asm__ volatile("casp w0, w1, w2, w3, [%4]" : "+r"(w0), "+r"(w1) : "r"(w2), "r"(w3), "r"(p) : "memory");
    int swapped = w0 == want[0] && w1 == want[1];
    want[0] = w0;
    want[1] = w1;
    return swapped;
}

// casp x30, xzr: compares `*p` with {want, 0}; returns what the first
// doubleword held.
LSE static unsigned long casp_zr(pair *p, unsigned long want, pair with) {
    register unsigned long x30 __asm__("x30") = want;
    register unsigned long x2 __asm__("x2") = with.lo;
    register unsigned long x3 __asm__("x3") = with.hi;
    __asm__ volatile("casp x30, xzr, x2, x3, [%3]" : "+r"(x30) : "r"(x2), "r"(x3), "r"(p) : "memory");
    return x30;
}

static void on_bus(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    bus_code = si->si_code;
    siglongjmp(out, 1);
}

#define ROUNDS 20000

static void *add_casp(void *bad) {
    for (int i = 0; i < ROUNDS; i++) {
        pair seen = {0, 0};
        for (;;) {
            pair next = {seen.lo + 1, seen.hi + 3};
            if (casp(&counter, &seen, next)) break;
            if (seen.hi != seen.lo * 3) *(int *)bad = 1;
        }
    }
    return 0;
}

static void *add_exclusive(void *bad) {
    for (int i = 0; i < ROUNDS; i++) {
        unsigned long lo, hi;
        unsigned int fail;
        do {
            __asm__ volatile("ldaxp %0, %1, [%3]\n\t"
                             "add %0, %0, #1\n\t"
                             "add %1, %1, #3\n\t"
                             "stlxp %w2, %0, %1, [%3]"
                             : "=&r"(lo), "=&r"(hi), "=&r"(fail)
                             : "r"(&counter)
                             : "memory");
        } while (fail);
        // What was stored was built from one instant's pair.
        if (hi != lo * 3) *(int *)bad = 1;
    }
    return 0;
}

// Loads the pair, lets the other thread change its second half, stores.
static void *load_wait_store(void *failed) {
    unsigned long lo, hi;
    unsigned int fail;
    __asm__ volatile("ldxp %0, %1, [%3]\n\t"
                     "mov w9, #1\n\t"
                     "str w9, [%4]\n\t"
                     "1: ldr w9, [%4]\n\t"
                     "cmp w9, #2\n\t"
                     "b.ne 1b\n\t"
                     "stxp %w2, %0, %1, [%3]"
                     : "=&r"(lo), "=&r"(hi), "=&r"(fail)
                     : "r"(&watched), "r"(&stage)
                     : "x9", "cc", "memory");
    *(unsigned int *)failed = fail;
    return 0;
}

int main(void) {
    int status = 0;

    pair want = {1, 2};
    if (!casp(&one, &want, (pair){30, 40}) || one.lo != 30 || one.hi != 40 || want.lo != 1 || want.hi != 2) status |= 1;
    want = (pair){30, 41};
    if (casp(&one, &want, (pair){5, 6}) || one.lo != 30 || one.hi != 40 || want.lo != 30 || want.hi != 40) status |= 2;
    want = (pair){31, 40};
    if (casp(&one, &want, (pair){5, 6}) || one.lo != 30 || one.hi != 40 || want.lo != 30 || want.hi != 40) status |= 2;

    unsigned int w[2] = {7, 9};
    if (!casp_w(words, w, 100, 200) || words[0] != 100 || words[1] != 200 || w[0] != 7 || w[1] != 9) status |= 4;
    w[0] = 100, w[1] = 201;
    if (casp_w(words, w, 1, 2) || words[0] != 100 || words[1] != 200 || w[0] != 100 || w[1] != 200) status |= 8;

    // {30, 40} is not {30, 0}; {30, 0} is.
    if (casp_zr(&one, 30, (pair){8, 9}) != 30 || one.lo != 30 || one.hi != 40) status |= 16;
    one.hi = 0;
    if (casp_zr(&one, 30, (pair){8, 9}) != 30 || one.lo != 8 || one.hi != 9) status |= 16;

    struct sigaction sa = {.sa_sigaction = on_bus, .sa_flags = SA_SIGINFO};
    sigaction(SIGBUS, &sa, 0);
    static unsigned long three[3] __attribute__((aligned(16))) = {1, 2, 3};
    if (sigsetjmp(out, 1) == 0) {
        want = (pair){2, 3};
        casp((pair *)&three[1], &want, (pair){5, 6});
        status |= 32;
    } else if (bus_code != BUS_ADRALN || three[1] != 2 || three[2] != 3) {
        status |= 32;
    }

    pthread_t t[4];
    int bad = 0;
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, i & 1 ? add_casp : add_exclusive, &bad);
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    if (bad || counter.lo != 4 * ROUNDS || counter.hi != 3 * counter.lo) status |= 64;

    unsigned int failed = 0;
    pthread_t waiter;
    pthread_create(&waiter, 0, load_wait_store, &failed);
    while (__atomic_load_n(&stage, __ATOMIC_SEQ_CST) != 1) {
    }
    want = (pair){40, 1};
    if (!casp(&watched, &want, (pair){40, 2})) status |= 128;
    __atomic_store_n(&stage, 2, __ATOMIC_SEQ_CST);
    pthread_join(waiter, 0);
    if (failed != 1 || watched.lo != 40 || watched.hi != 2) status |= 128;

    if (status) {
        printf("casp %d\n", status);
        return 1;
    }
    printf("casp ok\n");
    return 0;
}
