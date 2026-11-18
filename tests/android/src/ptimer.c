// POSIX timers (timer_create and the rest), as lmkd's watchdog and others
// use them: what the kernel refuses, timer ids, arming and reading back,
// a signal's siginfo (SI_TIMER, the id, the value, the overrun), a
// periodic timer's expirations, SIGEV_NONE, SIGEV_THREAD_ID, deletion,
// and that a child has none. Prints each answer and checks them against
// Linux 7.0's. The raw calls, so that the kernel's answers are seen.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "unknown clock: -22\n"
    "signal 0: -22\n"
    "signal 65: -22\n"
    "SIGEV_THREAD to the kernel: 0\n"
    "notify 9: -22\n"
    "another process's thread: -22\n"
    "bad sigevent pointer: -14\n"
    "bad id pointer: -14\n"
    "settime of no timer: -22\n"
    "gettime of no timer: -22\n"
    "delete of no timer: -22\n"
    "getoverrun of no timer: -22\n"
    "create: 0 0 0, ids in a row 1\n"
    "nsec 1e9: -22\n"
    "negative interval nsec: -22\n"
    "other flags: 0\n"
    "disarmed: 0 0 0 0\n"
    "armed: value 1 left, interval 7\n"
    "disarmed, old interval 7, old value set 1\n"
    "one shot: fired 1 code -2 id 1 value 77 overrun 0\n"
    "after it: 0 0\n"
    "absolute: fired 1\n"
    "absolute in the past: fired at once 1\n"
    "periodic, blocked: one signal 1, overrun near 19: 1, getoverrun agrees 1\n"
    "SIGEV_NONE: signals 0, left 0 0\n"
    "default: fired 1 code -2 value is the id 1\n"
    "own thread: 0\n"
    "delete: 0, then settime -22\n"
    "next id after the last: 1\n"
    "child has none: 1\n";

static char out_buf[4096];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[256];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    fflush(stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static long res(long r) {
    return r < 0 ? -errno : r;
}

// The kernel's struct sigevent.
struct ksigevent {
    union sigval value;
    int signo;
    int notify;
    int tid;
    int pad[11];
};

static long tcreate(clockid_t c, struct ksigevent *sev, int *id) {
    return res(syscall(__NR_timer_create, c, sev, id));
}

static long tset(int id, int flags, long v_s, long v_ns, long i_s, long i_ns, struct itimerspec *old) {
    struct itimerspec its = {{i_s, i_ns}, {v_s, v_ns}};
    return res(syscall(__NR_timer_settime, id, flags, &its, old));
}

static volatile int got_code, got_id, got_value, got_overrun, got_count;

static void on_sig(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    got_code = si->si_code;
    got_id = si->si_timerid;
    got_value = si->si_value.sival_int;
    got_overrun = si->si_overrun;
    got_count++;
}

static int waitfor(int count, int ms) {
    for (int i = 0; i < ms && got_count < count; i++)
        usleep(1000);
    return got_count >= count;
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN + 2, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    // Refusals.
    int id = -1;
    struct ksigevent sev = {0};
    sev.notify = SIGEV_SIGNAL;
    sev.signo = SIGRTMIN + 2;
    SAY("unknown clock: %ld\n", tcreate(99, &sev, &id));
    struct ksigevent bad = sev;
    bad.signo = 0;
    SAY("signal 0: %ld\n", tcreate(CLOCK_MONOTONIC, &bad, &id));
    bad.signo = 65;
    SAY("signal 65: %ld\n", tcreate(CLOCK_MONOTONIC, &bad, &id));
    bad = sev;
    bad.notify = SIGEV_THREAD;
    // The kernel takes SIGEV_THREAD as SIGEV_SIGNAL (libc does the rest).
    SAY("SIGEV_THREAD to the kernel: %ld\n", tcreate(CLOCK_MONOTONIC, &bad, &id));
    syscall(__NR_timer_delete, id);
    bad.notify = 9;
    SAY("notify 9: %ld\n", tcreate(CLOCK_MONOTONIC, &bad, &id));
    bad.notify = SIGEV_THREAD_ID;
    pid_t other = fork();
    if (other == 0) {
        pause();
        _exit(0);
    }
    bad.tid = other;
    SAY("another process's thread: %ld\n", tcreate(CLOCK_MONOTONIC, &bad, &id));
    kill(other, SIGKILL);
    waitpid(other, NULL, 0);
    SAY("bad sigevent pointer: %ld\n", tcreate(CLOCK_MONOTONIC, (void *)8, &id));
    SAY("bad id pointer: %ld\n", tcreate(CLOCK_MONOTONIC, &sev, (void *)8));
    SAY("settime of no timer: %ld\n", tset(1234, 0, 1, 0, 0, 0, NULL));
    SAY("gettime of no timer: %ld\n", res(syscall(__NR_timer_gettime, 1234, &(struct itimerspec){0})));
    SAY("delete of no timer: %ld\n", res(syscall(__NR_timer_delete, 1234)));
    SAY("getoverrun of no timer: %ld\n", res(syscall(__NR_timer_getoverrun, 1234)));

    // Ids: each the one after the last.
    int a = -1, b = -1, c = -1;
    sev.value.sival_int = 77;
    long ra = tcreate(CLOCK_MONOTONIC, &sev, &a);
    long rb = tcreate(CLOCK_REALTIME, NULL, &b);
    struct ksigevent none = {0};
    none.notify = SIGEV_NONE;
    long rc = tcreate(CLOCK_BOOTTIME, &none, &c);
    SAY("create: %ld %ld %ld, ids in a row %d\n", ra, rb, rc, b == a + 1 && c == b + 1);

    // Arguments to settime.
    SAY("nsec 1e9: %ld\n", tset(a, 0, 0, 1000000000, 0, 0, NULL));
    SAY("negative interval nsec: %ld\n", tset(a, 0, 1, 0, 0, -1, NULL));
    // Other flag bits are ignored.
    SAY("other flags: %ld\n", tset(a, 0x10, 1, 0, 0, 0, NULL));
    tset(a, 0, 0, 0, 0, 0, NULL);

    // Disarmed reads zero; armed reads what is left.
    struct itimerspec cur;
    syscall(__NR_timer_gettime, a, &cur);
    SAY("disarmed: %ld %ld %ld %ld\n", (long)cur.it_value.tv_sec, cur.it_value.tv_nsec, (long)cur.it_interval.tv_sec, cur.it_interval.tv_nsec);
    tset(a, 0, 100, 0, 7, 0, NULL);
    syscall(__NR_timer_gettime, a, &cur);
    SAY("armed: value %ld left, interval %ld\n", (long)(cur.it_value.tv_sec > 98 && cur.it_value.tv_sec <= 100), (long)cur.it_interval.tv_sec);
    struct itimerspec old;
    tset(a, 0, 0, 0, 0, 0, &old);
    SAY("disarmed, old interval %ld, old value set %d\n", (long)old.it_interval.tv_sec, old.it_value.tv_sec > 0);

    // One shot: SI_TIMER, the id, the value, no overrun.
    got_count = 0;
    tset(a, 0, 0, 20 * 1000 * 1000, 0, 0, NULL);
    SAY("one shot: fired %d code %d id %d value %d overrun %d\n", waitfor(1, 2000), got_code, got_id == a, got_value, got_overrun);
    syscall(__NR_timer_gettime, a, &cur);
    SAY("after it: %ld %ld\n", (long)cur.it_value.tv_sec, cur.it_value.tv_nsec);

    // Absolute time.
    got_count = 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long ns = now.tv_nsec + 30 * 1000 * 1000, s = now.tv_sec + ns / 1000000000;
    tset(a, TIMER_ABSTIME, s, ns % 1000000000, 0, 0, NULL);
    SAY("absolute: fired %d\n", waitfor(1, 2000));
    tset(a, TIMER_ABSTIME, 1, 0, 0, 0, NULL);
    usleep(20000);
    SAY("absolute in the past: fired at once %d\n", got_count == 2);

    // Periodic, with the signal blocked: one signal, the rest overruns.
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGRTMIN + 2);
    sigprocmask(SIG_BLOCK, &m, NULL);
    got_count = 0;
    tset(a, 0, 0, 10 * 1000 * 1000, 0, 10 * 1000 * 1000, NULL);
    usleep(205 * 1000);
    sigprocmask(SIG_UNBLOCK, &m, NULL);
    waitfor(1, 500);
    long over = res(syscall(__NR_timer_getoverrun, a));
    tset(a, 0, 0, 0, 0, 0, NULL);
    SAY("periodic, blocked: one signal %d, overrun near 19: %d, getoverrun agrees %d\n", got_count >= 1 && got_count <= 2, got_overrun >= 14 && got_overrun <= 22, over == got_overrun);

    // SIGEV_NONE: nothing sent, still read back.
    got_count = 0;
    tset(c, 0, 0, 10 * 1000 * 1000, 0, 0, NULL);
    usleep(50000);
    syscall(__NR_timer_gettime, c, &cur);
    SAY("SIGEV_NONE: signals %d, left %ld %ld\n", got_count, (long)cur.it_value.tv_sec, cur.it_value.tv_nsec);

    // NULL sigevent: SIGALRM, the value being the id.
    got_count = 0;
    tset(b, 0, 0, 10 * 1000 * 1000, 0, 0, NULL);
    SAY("default: fired %d code %d value is the id %d\n", waitfor(1, 2000), got_code, got_value == b);

    // A thread of this process by id.
    struct ksigevent own = sev;
    own.notify = SIGEV_THREAD_ID;
    own.tid = (int)syscall(__NR_gettid);
    int d = -1;
    SAY("own thread: %ld\n", tcreate(CLOCK_MONOTONIC, &own, &d));

    // Deleted: gone, and its id is not given again at once.
    SAY("delete: %ld, then settime %ld\n", res(syscall(__NR_timer_delete, b)), tset(b, 0, 1, 0, 0, 0, NULL));
    int e = -1;
    tcreate(CLOCK_MONOTONIC, &sev, &e);
    SAY("next id after the last: %d\n", e == d + 1);

    // A child has none.
    pid_t p = fork();
    if (p == 0)
        _exit(res(syscall(__NR_timer_gettime, a, &cur)) == -EINVAL ? 0 : 1);
    int st = 0;
    waitpid(p, &st, 0);
    SAY("child has none: %d\n", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("ptimer: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "ptimer ok\n" : "ptimer done\n");
    return 0;
}
