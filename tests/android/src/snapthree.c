// snapone's test with an event loop: a snapshot taken partway, resumed,
// must go on as the whole run does. One thread waits in epoll on
// - a periodic timerfd (its expiries counted),
// - an eventfd it writes to itself, once a step,
// - a signalfd for SIGUSR1, which it sends itself every fifth step;
// and the run ends at an absolute deadline on the monotonic clock, taken
// at its start: a resumed run's clocks go on from the snapshot's, so the
// deadline is neither past at once nor far away.
// What it prints does not depend on timing.
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define N 30

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint64_t start = now_ns();
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    int efd = eventfd(0, EFD_CLOEXEC);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    int sfd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (ep < 0 || tfd < 0 || efd < 0 || sfd < 0) {
        printf("setup failed\n");
        return 1;
    }
    struct itimerspec it = {{0, 30 * 1000 * 1000}, {0, 30 * 1000 * 1000}};
    timerfd_settime(tfd, 0, &it, NULL);
    struct epoll_event ev = {.events = EPOLLIN};
    ev.data.u32 = 1;
    epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev);
    ev.data.u32 = 2;
    epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev);
    ev.data.u32 = 3;
    epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &ev);

    uint64_t ticks = 0, sigs = 0;
    for (int step = 1; step <= N; step++) {
        uint64_t one = 1;
        write(efd, &one, sizeof one);
        if (step % 5 == 0) kill(getpid(), SIGUSR1);
        // Wait for this step's event (and the signal on its steps).
        int want_sig = step % 5 == 0, got_event = 0, got_sig = 0;
        while (!got_event || (want_sig && !got_sig)) {
            struct epoll_event out[4];
            int n = epoll_wait(ep, out, 4, 1000);
            for (int i = 0; i < n; i++) {
                uint64_t v;
                if (out[i].data.u32 == 1 && read(tfd, &v, sizeof v) == sizeof v) ticks += v;
                if (out[i].data.u32 == 2 && read(efd, &v, sizeof v) == sizeof v) got_event = 1;
                if (out[i].data.u32 == 3) {
                    struct signalfd_siginfo si;
                    if (read(sfd, &si, sizeof si) == sizeof si && si.ssi_signo == SIGUSR1) got_sig = 1, sigs++;
                }
            }
        }
        // A step lasts a little: the timer goes off between steps.
        struct timespec ts = {0, 40 * 1000 * 1000};
        nanosleep(&ts, NULL);
        printf("step %d event%s\n", step, want_sig ? " signal" : "");
    }
    // The absolute deadline: two seconds after the start, by the
    // monotonic clock read at the start.
    uint64_t deadline = start + 2000000000ull;
    struct timespec dl = {(time_t)(deadline / 1000000000ull), (long)(deadline % 1000000000ull)};
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &dl, NULL);
    uint64_t after = now_ns();
    int on_time = after >= deadline && after - start < 60000000000ull;
    printf("%s\n", on_time && ticks > 0 && sigs == N / 5 ? "snapthree ok" : "snapthree: lost time, ticks or signals");
    return 0;
}
