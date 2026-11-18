/* A thread is handed a pointer into memory another thread has just mapped,
 * and does a locked compare-and-swap on it at once, as FL Studio's FastMM
 * did. Each mapping grows the process's memory. Thread B spins on a round
 * counter, which is plain memory: no call into the kernel between its
 * reading the pointer and its use. The engine gives a Worker the new length
 * of a shared memory another Worker grew only at its own next interrupt, so
 * B trapped out of bounds on memory that was there (test/native/stale-bound,
 * test/core/stale-bound). Built as a wasm32 probe and, for the translated
 * tiers, with the guest's cross compiler.
 *
 *   rt-stalebound [ROUNDS]   prints "stale-bound ok ROUNDS" */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define MAP (48u << 20)

static _Atomic(long *) shared;
static atomic_int round_no, done_no;
static int rounds = 30;

static void *b(void *arg) {
    (void)arg;
    for (int r = 1; r <= rounds; r++) {
        while (atomic_load_explicit(&round_no, memory_order_acquire) != r)
            ;
        long *p = atomic_load_explicit(&shared, memory_order_acquire);
        long expect = 0;
        __atomic_compare_exchange_n(p, &expect, (long)r, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        p[1] = r;
        atomic_store(&done_no, r);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) rounds = atoi(argv[1]);
    pthread_t t;
    if (pthread_create(&t, 0, b, 0)) {
        printf("no thread\n");
        return 1;
    }
    for (int r = 1; r <= rounds; r++) {
        long *p = mmap(0, MAP, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("mmap failed in round %d\n", r);
            return 1;
        }
        /* the mapping's last page: the newest memory */
        long *q = (long *)((char *)p + MAP - 4096);
        atomic_store_explicit(&shared, q, memory_order_release);
        atomic_store_explicit(&round_no, r, memory_order_release);
        while (atomic_load(&done_no) != r)
            ;
        if (q[0] != r || q[1] != r) {
            printf("round %d: %ld %ld\n", r, q[0], q[1]);
            return 1;
        }
    }
    pthread_join(t, 0);
    printf("stale-bound ok %d\n", rounds);
    return 0;
}
