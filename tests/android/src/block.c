// Calls that wait, given bionic's tagged heap pointers: a read and a readv
// that block on a pipe, poll, select and epoll_wait that block on it, a
// wait for a child, and a condition variable in a heap object. The kernel
// finishes each one after the thread has slept, at the address it was
// given, tag and all.
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                          \
    do {                                                  \
        if (!(c)) {                                       \
            printf("%s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                     \
        }                                                 \
    } while (0)

static int tagged(const void *p) {
    return (uintptr_t)p >> 56 != 0;
}

static int fds[2];

// Writes `arg` bytes to the pipe once the main thread has had time to wait.
static void *write_later(void *arg) {
    usleep(50 * 1000);
    static const char text[] = "abcdefgh";
    if (write(fds[1], text, (size_t)arg) != (ssize_t)(size_t)arg) abort();
    return 0;
}

struct gate {
    pthread_mutex_t lock;
    pthread_cond_t open;
    int is_open;
};

static void *open_later(void *arg) {
    struct gate *g = arg;
    usleep(50 * 1000);
    pthread_mutex_lock(&g->lock);
    g->is_open = 1;
    pthread_cond_signal(&g->open);
    pthread_mutex_unlock(&g->lock);
    return 0;
}

int main(void) {
    pthread_t t;
    CHECK(pipe(fds) == 0);

    char *buf = malloc(64);
    CHECK(buf && tagged(buf));
    CHECK(pthread_create(&t, 0, write_later, (void *)1) == 0);
    CHECK(read(fds[0], buf, 64) == 1 && buf[0] == 'a');
    pthread_join(t, 0);

    struct iovec *iov = malloc(2 * sizeof *iov);
    char *first = malloc(3), *second = malloc(8);
    CHECK(iov && first && second && tagged(iov) && tagged(first));
    iov[0] = (struct iovec){first, 3};
    iov[1] = (struct iovec){second, 8};
    CHECK(pthread_create(&t, 0, write_later, (void *)5) == 0);
    CHECK(readv(fds[0], iov, 2) == 5 && first[2] == 'c' && second[1] == 'e');
    pthread_join(t, 0);

    struct pollfd *p = malloc(sizeof *p);
    CHECK(p && tagged(p));
    *p = (struct pollfd){.fd = fds[0], .events = POLLIN};
    CHECK(pthread_create(&t, 0, write_later, (void *)1) == 0);
    CHECK(poll(p, 1, -1) == 1 && p->revents == POLLIN);
    pthread_join(t, 0);
    CHECK(read(fds[0], buf, 64) == 1);

    fd_set *set = malloc(sizeof *set);
    CHECK(set && tagged(set));
    FD_ZERO(set);
    FD_SET(fds[0], set);
    CHECK(pthread_create(&t, 0, write_later, (void *)1) == 0);
    CHECK(select(fds[0] + 1, set, 0, 0, 0) == 1 && FD_ISSET(fds[0], set));
    pthread_join(t, 0);
    CHECK(read(fds[0], buf, 64) == 1);

    int ep = epoll_create1(0);
    struct epoll_event *ev = malloc(2 * sizeof *ev);
    CHECK(ep >= 0 && ev && tagged(ev));
    ev[0] = (struct epoll_event){.events = EPOLLIN, .data.u64 = 0x1122334455667788ull};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], ev) == 0);
    ev[0].data.u64 = 0;
    CHECK(pthread_create(&t, 0, write_later, (void *)1) == 0);
    CHECK(epoll_wait(ep, ev, 2, -1) == 1 && ev[0].events == EPOLLIN && ev[0].data.u64 == 0x1122334455667788ull);
    pthread_join(t, 0);
    CHECK(read(fds[0], buf, 64) == 1);

    int *status = malloc(sizeof *status);
    CHECK(status && tagged(status));
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        usleep(50 * 1000);
        _exit(7);
    }
    CHECK(waitpid(child, status, 0) == child && WIFEXITED(*status) && WEXITSTATUS(*status) == 7);

    struct gate *g = malloc(sizeof *g);
    CHECK(g && tagged(g));
    pthread_mutex_init(&g->lock, 0);
    pthread_cond_init(&g->open, 0);
    g->is_open = 0;
    CHECK(pthread_create(&t, 0, open_later, g) == 0);
    pthread_mutex_lock(&g->lock);
    while (!g->is_open) pthread_cond_wait(&g->open, &g->lock);
    pthread_mutex_unlock(&g->lock);
    pthread_join(t, 0);

    printf("block ok\n");
    return 0;
}
