// Setting the wall clock and the time zone: `settimeofday`, as Android's
// init does for `sysclktz 0` (a zone and no time), and `clock_settime`; and
// a timerfd armed to be cancelled by a set (TFD_TIMER_CANCEL_ON_SET), as
// alarm code waits on the wall clock.
//
// As root. The machine's own clock is moved forward 1000 s and put back
// at once, by the monotonic clock: on a real machine that is a few
// milliseconds of wrong time.
//
// - a zone more than fifteen hours from Greenwich is EINVAL; a zone is
//   given back by gettimeofday;
// - a time with tv_usec out of range or before the epoch is EINVAL, and
//   that before the capability is looked at;
// - without CAP_SYS_TIME (a child that has become uid 1000) a zone or a
//   time is EPERM, a zone out of range too;
// - clock_settime of the monotonic clock, the process's or thread's CPU
//   clock or an unknown one is EINVAL, and of the wall clock with tv_nsec
//   out of range;
// - timerfd_settime with an unknown flag, or tv_nsec out of range, is
//   EINVAL;
// - a wall-clock timerfd armed absolute with TFD_TIMER_CANCEL_ON_SET: a
//   set makes it readable and the read ECANCELED, once; the clock reads
//   what it was set to.
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

static void fail(const char *what, long got, long want) {
    printf("settod: %s: got %ld (errno %d), wanted %ld\n", what, got, errno, want);
    exit(1);
}

// The call's -errno, or its result.
#define R(call) ((call) == 0 ? 0L : -(long)errno)

static int64_t ns(clockid_t c) {
    struct timespec t;
    clock_gettime(c, &t);
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void expect(const char *what, long got, long want) {
    if (got != want) fail(what, got, want);
}

static long tod(long sec, long usec, const struct timezone *tz) {
    struct timeval tv = {sec, usec};
    return R(settimeofday(&tv, tz));
}

static long cset(clockid_t c, long sec, long nsec) {
    struct timespec t = {sec, nsec};
    return R(clock_settime(c, &t));
}

int main(void) {
    struct timezone utc = {0, 0}, east = {-120, 0}, far = {901, 0}, farther = {-901, 0};
    struct timeval tv;
    struct timezone got;

    // The zone: init's `sysclktz 0`, and one given back.
    expect("settimeofday(NULL, east)", R(settimeofday(NULL, &east)), 0);
    expect("gettimeofday", R(gettimeofday(&tv, &got)), 0);
    expect("the zone given back", got.tz_minuteswest, -120);
    expect("settimeofday(NULL, utc)", R(settimeofday(NULL, &utc)), 0);
    expect("gettimeofday", R(gettimeofday(&tv, &got)), 0);
    expect("the zone given back", got.tz_minuteswest, 0);
    expect("a zone 901 minutes west", R(settimeofday(NULL, &far)), -EINVAL);
    expect("a zone 901 minutes east", R(settimeofday(NULL, &farther)), -EINVAL);

    // Times out of range.
    gettimeofday(&tv, NULL);
    expect("tv_usec 1000001", tod(tv.tv_sec, 1000001, NULL), -EINVAL);
    expect("tv_usec 1000000", tod(tv.tv_sec, 1000000, NULL), -EINVAL);
    expect("tv_usec -1", tod(tv.tv_sec, -1, NULL), -EINVAL);
    expect("tv_sec -1", tod(-1, 0, NULL), -EINVAL);

    // clock_settime of clocks that cannot be set.
    expect("clock_settime(MONOTONIC)", cset(CLOCK_MONOTONIC, tv.tv_sec, 0), -EINVAL);
    expect("clock_settime(BOOTTIME)", cset(CLOCK_BOOTTIME, tv.tv_sec, 0), -EINVAL);
    expect("clock_settime(100)", cset(100, tv.tv_sec, 0), -EINVAL);
    expect("clock_settime(PROCESS_CPUTIME_ID)", cset(CLOCK_PROCESS_CPUTIME_ID, 0, 0), -EINVAL);
    expect("clock_settime(THREAD_CPUTIME_ID)", cset(CLOCK_THREAD_CPUTIME_ID, 0, 0), -EINVAL);
    expect("clock_settime(REALTIME, tv_nsec 1e9)", cset(CLOCK_REALTIME, tv.tv_sec, 1000000000), -EINVAL);

    // Without CAP_SYS_TIME.
    pid_t child = fork();
    if (child < 0) fail("fork", -errno, 0);
    if (child == 0) {
        if (setgid(1000) || setuid(1000)) _exit(10);
        if (settimeofday(NULL, &utc) == 0 || errno != EPERM) _exit(11);
        if (settimeofday(NULL, &far) == 0 || errno != EPERM) _exit(12);
        gettimeofday(&tv, NULL);
        if (tod(tv.tv_sec, -1, NULL) != -EINVAL) _exit(13);
        if (tod(tv.tv_sec, 0, NULL) != -EPERM) _exit(14);
        if (cset(CLOCK_REALTIME, tv.tv_sec, 0) != -EPERM) _exit(15);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) fail("the child", status, 0);
    expect("the child without CAP_SYS_TIME", WEXITSTATUS(status), 0);

    // timerfd_settime's checks, and a timer armed to be cancelled.
    int fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) fail("timerfd_create", -errno, 0);
    struct itimerspec its = {{0, 0}, {0, 0}};
    its.it_value.tv_sec = time(NULL) + 3600;
    expect("timerfd_settime flag 4", R(timerfd_settime(fd, 4, &its, NULL)), -EINVAL);
    its.it_value.tv_nsec = 1000000000;
    expect("timerfd_settime tv_nsec 1e9", R(timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL)), -EINVAL);
    its.it_value.tv_nsec = 0;
    expect("timerfd_settime to be cancelled", R(timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &its, NULL)), 0);
    uint64_t ticks;
    expect("a read before a set", read(fd, &ticks, 8) < 0 ? -errno : 0, -EAGAIN);

    // Forward 1000 s, and back by the monotonic clock.
    int64_t m0 = ns(CLOCK_MONOTONIC), r0 = ns(CLOCK_REALTIME);
    int64_t ahead = r0 + 1000LL * 1000000000;
    expect("clock_settime(REALTIME) ahead", cset(CLOCK_REALTIME, ahead / 1000000000, ahead % 1000000000), 0);
    int64_t r1 = ns(CLOCK_REALTIME), m1 = ns(CLOCK_MONOTONIC);
    int64_t back = r0 + (m1 - m0);
    expect("settimeofday back", tod(back / 1000000000, back % 1000000000 / 1000, NULL), 0);
    long off = (long)((r1 - ahead) / 1000000);
    if (off < 0 || off > 2000) fail("the clock after it was set ahead (ms past what was set)", off, 0);
    long drift = (long)((ns(CLOCK_REALTIME) - (r0 + (ns(CLOCK_MONOTONIC) - m0))) / 1000000);
    if (drift < -2000 || drift > 2000) fail("the clock put back (ms from where it was)", drift, 0);

    struct pollfd p = {fd, POLLIN, 0};
    expect("poll after a set", poll(&p, 1, 0), 1);
    expect("a read after a set", read(fd, &ticks, 8) < 0 ? -errno : 0, -ECANCELED);
    expect("the read after that", read(fd, &ticks, 8) < 0 ? -errno : 0, -EAGAIN);
    struct itimerspec left;
    timerfd_gettime(fd, &left);
    if (left.it_value.tv_sec <= 0) fail("still armed after the cancel", left.it_value.tv_sec, 1);

    printf("settod ok\n");
    return 0;
}
