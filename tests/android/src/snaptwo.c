// snapone's test with threads: a snapshot taken partway, resumed, must go
// on as the whole run does. Three threads:
// - main hands steps 1..N to `waiter` through a mutex and condition
//   variable (futexes), and prints each step once `waiter` has it;
// - `waiter` waits on the condition variable for each step, and checks
//   its thread id and its thread-local value are still its own;
// - `ticker` sleeps and counts on its own, likewise checking its id.
// Only main prints, so what is printed does not depend on timing.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define N 40

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int given, taken;
static atomic_int ticks, lost;
static atomic_int done;
static __thread long mine;

static void nap(long ms) {
    struct timespec ts = {0, ms * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static void *waiter(void *arg) {
    (void)arg;
    pid_t me = (pid_t)syscall(SYS_gettid);
    mine = me * 3;
    for (int i = 1; i <= N; i++) {
        pthread_mutex_lock(&mu);
        while (given < i) pthread_cond_wait(&cv, &mu);
        if ((pid_t)syscall(SYS_gettid) != me || mine != me * 3) atomic_fetch_add(&lost, 1);
        taken = i;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

static void *ticker(void *arg) {
    (void)arg;
    pid_t me = (pid_t)syscall(SYS_gettid);
    mine = me * 5;
    while (!atomic_load(&done)) {
        nap(20);
        if ((pid_t)syscall(SYS_gettid) != me || mine != me * 5) atomic_fetch_add(&lost, 1);
        atomic_fetch_add(&ticks, 1);
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t w, t;
    pthread_create(&w, NULL, waiter, NULL);
    pthread_create(&t, NULL, ticker, NULL);
    for (int i = 1; i <= N; i++) {
        nap(40);
        pthread_mutex_lock(&mu);
        given = i;
        pthread_cond_broadcast(&cv);
        while (taken < i) pthread_cond_wait(&cv, &mu);
        pthread_mutex_unlock(&mu);
        printf("step %d taken %d %s\n", i, taken, atomic_load(&lost) ? "LOST" : "kept");
    }
    atomic_store(&done, 1);
    pthread_join(w, NULL);
    pthread_join(t, NULL);
    printf("%s\n", !atomic_load(&lost) && atomic_load(&ticks) > 0 ? "snaptwo ok" : "snaptwo: a thread lost its state");
    return 0;
}
