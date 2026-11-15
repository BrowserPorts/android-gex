// A wait lasts what it says, by the clocks the program reads: never less,
// and not much more. Programs give one another time in seconds (Android's
// apexd gives ueventd twenty to make a device node), and a kernel whose
// clocks and waits disagree lets a timeout go off early or never.
//
// Each of these waits a set time with nothing to end it sooner, and the
// monotonic clock is read before and after:
// - nanosleep, and clock_nanosleep to a time on the clock (TIMER_ABSTIME);
// - poll and epoll_wait with a timeout and nothing ready;
// - a futex wait with a timeout (ETIMEDOUT);
// - rt_sigtimedwait for a signal nobody sends (EAGAIN);
// - a read of a timerfd set to go off once;
// - a sleep an interval timer's SIGALRM ends (EINTR), at the timer's time.
// And the realtime clock goes at the monotonic clock's rate.
//
// gex can run a program with its time slowed (GEX_TIME_SCALE), and then
// all of this still holds by the program's own clocks: run.sh runs it both
// ways.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("waits: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static int64_t now(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) die("clock_gettime", clock, 0);
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

// A wait of `want` milliseconds began at `from`: it took that long, and
// not more than three times that and half a second.
static void took(const char *what, int64_t from, long want) {
    long ms = (long)((now(CLOCK_MONOTONIC) - from) / 1000000);
    if (ms < want || ms > want * 3 + 500) die(what, ms, want);
}

static struct timespec ms(long n) {
    return (struct timespec){n / 1000, n % 1000 * 1000000};
}

static void on_alarm(int sig) {
    (void)sig;
}

int main(void) {
    int64_t t = now(CLOCK_MONOTONIC), wall = now(CLOCK_REALTIME);
    struct timespec d = ms(120);
    if (nanosleep(&d, NULL)) die("nanosleep", errno, 0);
    took("nanosleep", t, 120);
    // The two clocks went the same way: within 50 ms of each other.
    int64_t mono = now(CLOCK_MONOTONIC) - t, real = now(CLOCK_REALTIME) - wall;
    if (real - mono > 50000000 || mono - real > 50000000) die("the realtime clock's rate", (long)(mono / 1000000), (long)(real / 1000000));

    t = now(CLOCK_MONOTONIC);
    int64_t until = t + 90 * 1000000;
    struct timespec abs = {until / 1000000000, until % 1000000000};
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &abs, NULL)) die("clock_nanosleep", errno, 0);
    took("clock_nanosleep to a time", t, 90);

    int p[2];
    if (pipe(p)) die("pipe", errno, 0);
    struct pollfd pf = {p[0], POLLIN, 0};
    t = now(CLOCK_MONOTONIC);
    if (poll(&pf, 1, 80) != 0) die("poll", errno, pf.revents);
    took("poll", t, 80);

    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN}, got;
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev)) die("epoll", errno, 0);
    t = now(CLOCK_MONOTONIC);
    if (epoll_wait(ep, &got, 1, 60) != 0) die("epoll_wait", errno, 0);
    took("epoll_wait", t, 60);

    static uint32_t word = 7;
    d = ms(70);
    t = now(CLOCK_MONOTONIC);
    if (syscall(SYS_futex, &word, FUTEX_WAIT, 7, &d, NULL, 0) != -1 || errno != ETIMEDOUT) die("futex", errno, 0);
    took("a futex wait", t, 70);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    d = ms(50);
    t = now(CLOCK_MONOTONIC);
    if (sigtimedwait(&set, NULL, &d) != -1 || errno != EAGAIN) die("sigtimedwait", errno, 0);
    took("sigtimedwait", t, 50);

    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec once = {.it_value = ms(100)};
    uint64_t fired = 0;
    t = now(CLOCK_MONOTONIC);
    if (tfd < 0 || timerfd_settime(tfd, 0, &once, NULL) || read(tfd, &fired, 8) != 8 || fired != 1) die("timerfd", errno, (long)fired);
    took("a timerfd", t, 100);

    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = {.it_value = {0, 150000}};
    d = ms(5000);
    t = now(CLOCK_MONOTONIC);
    if (setitimer(ITIMER_REAL, &it, NULL)) die("setitimer", errno, 0);
    if (nanosleep(&d, NULL) != -1 || errno != EINTR) die("a sleep an alarm ends", errno, 0);
    took("an interval timer", t, 150);

    printf("waits ok\n");
    return 0;
}
