// What futex answers: a wake counts the waiters it woke, not the number
// asked for (asked for everyone, that is -1 to a caller that reads an int,
// which ART takes for a failure); a requeue counts those it woke and
// moved; a compare-requeue is EAGAIN when the word has changed. A waiter
// woken early waits again, so a count is the same whether waiters were
// moved or woken.
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(c)                                          \
    do {                                                  \
        if (!(c)) {                                       \
            printf("%s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                     \
        }                                                 \
    } while (0)

static _Atomic int a, b, go, waiting;

static long futex(void *addr, int op, long val, long val2, void *addr2, long val3) {
    return syscall(SYS_futex, addr, op, val, val2, addr2, val3);
}

// Waits on `a` until told to go, whoever wakes it and wherever it was moved.
static void *waiter(void *arg) {
    (void)arg;
    atomic_fetch_add(&waiting, 1);
    while (!atomic_load(&go)) futex(&a, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    return 0;
}

int main(void) {
    CHECK(futex(&a, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0) == 0);
    CHECK(futex(&a, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) == 0);
    CHECK(futex(&a, FUTEX_REQUEUE_PRIVATE, 0, INT_MAX, &b, 0) == 0);
    CHECK(futex(&a, FUTEX_CMP_REQUEUE_PRIVATE, 1, INT_MAX, &b, 0) == 0);
    CHECK(futex(&a, FUTEX_CMP_REQUEUE_PRIVATE, 1, INT_MAX, &b, 7) == -1 && errno == EAGAIN);

    pthread_t t[2];
    for (int i = 0; i < 2; i++) CHECK(pthread_create(&t[i], 0, waiter, 0) == 0);
    while (atomic_load(&waiting) < 2) usleep(1000);
    usleep(200 * 1000);

    // Both are counted, moved or woken.
    CHECK(futex(&a, FUTEX_REQUEUE_PRIVATE, 0, INT_MAX, &b, 0) == 2);
    usleep(200 * 1000);
    // And again, if they are back on the first word; none if they moved.
    long again = futex(&a, FUTEX_CMP_REQUEUE_PRIVATE, 1, INT_MAX, &b, 0);
    CHECK(again == 0 || again == 2);
    usleep(200 * 1000);

    atomic_store(&go, 1);
    long woke = futex(&a, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0) + futex(&b, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0);
    CHECK(woke >= 0 && woke <= 2);
    for (int i = 0; i < 2; i++) pthread_join(t[i], 0);
    CHECK(futex(&a, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0) == 0);

    printf("futex ok\n");
    return 0;
}
