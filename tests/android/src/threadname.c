// A thread's name set and read by another thread of the process, as
// bionic does it (pthread_setname_np and pthread_getname_np on a thread
// that is not the caller: /proc/self/task/<tid>/comm, opened for writing
// or reading), and by the thread itself (prctl PR_SET_NAME): the name is
// kept to 15 bytes, a longer one is ERANGE, and /proc/self/task/<tid>/comm
// reads it back with a newline; written there directly, its first 15 bytes
// are the name as they are. The composer HAL names its vsync thread
// this way.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("threadname: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static void want_s(const char *what, const char *got, const char *expect) {
    if (strcmp(got, expect) != 0) {
        printf("threadname: %s: want '%s', got '%s'\n", what, expect, got);
        failed = 1;
    }
}

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c = PTHREAD_COND_INITIALIZER;
static int done, tid;

static void *idle(void *arg) {
    (void)arg;
    pthread_mutex_lock(&m);
    tid = gettid();
    pthread_cond_broadcast(&c);
    while (!done) pthread_cond_wait(&c, &m);
    pthread_mutex_unlock(&m);
    return NULL;
}

static void comm_of(int t, char *out, size_t n) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", t);
    int fd = open(path, O_RDONLY);
    long r = fd < 0 ? -1 : read(fd, out, n - 1);
    if (fd >= 0) close(fd);
    out[r > 0 ? r : 0] = 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, idle, NULL);
    pthread_mutex_lock(&m);
    while (!tid) pthread_cond_wait(&c, &m);
    pthread_mutex_unlock(&m);

    char b[64];
    want("set another's name", pthread_setname_np(t, "thread"), 0);
    memset(b, 0, sizeof b);
    want("get another's name", pthread_getname_np(t, b, sizeof b), 0);
    want_s("another's name", b, "thread");
    comm_of(tid, b, sizeof b);
    want_s("its comm", b, "thread\n");
    want("a 15-byte name", pthread_setname_np(t, "abcdefghijklmno"), 0);
    comm_of(tid, b, sizeof b);
    want_s("its comm", b, "abcdefghijklmno\n");
    want("a 16-byte name", pthread_setname_np(t, "abcdefghijklmnop"), ERANGE);
    want("a short buffer", pthread_getname_np(t, b, 4), ERANGE);

    // Written to the file directly (comm_write): the first 15 bytes as
    // they are, the whole count answered; a newline is part of the name.
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid);
    int fd = open(path, O_WRONLY);
    want("open its comm for writing", fd >= 0, 1);
    want("write a long name", write(fd, "0123456789abcdefghij", 20), 20);
    close(fd);
    comm_of(tid, b, sizeof b);
    want_s("cut to 15", b, "0123456789abcde\n");
    fd = open(path, O_WRONLY);
    want("write with a newline", write(fd, "xyz\n", 4), 4);
    close(fd);
    comm_of(tid, b, sizeof b);
    want_s("the newline kept", b, "xyz\n\n");

    // Its own, by prctl, as bionic names the calling thread.
    want("PR_SET_NAME", prctl(PR_SET_NAME, "mainname"), 0);
    memset(b, 0, sizeof b);
    want("PR_GET_NAME", prctl(PR_GET_NAME, b), 0);
    want_s("its own name", b, "mainname");
    comm_of(gettid(), b, sizeof b);
    want_s("its own comm", b, "mainname\n");

    pthread_mutex_lock(&m);
    done = 1;
    pthread_cond_broadcast(&c);
    pthread_mutex_unlock(&m);
    pthread_join(t, NULL);
    if (!failed) printf("threadname ok\n");
    return failed;
}
