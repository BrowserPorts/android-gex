// Job control: SIGSTOP and SIGCONT as Linux's do_signal_stop and
// prepare_signal have them. Everything runs under a first child of the
// test, so that no process here has init as its parent (an orphaned
// process group is judged by parents in the session, init not counting).
//
// A child with two threads writes to a pipe every 5 ms: stopped, nothing
// more comes, /proc says T, the parent's SIGCHLD says CLD_STOPPED with
// SIGSTOP and a WUNTRACED wait reports it once; continued, writes come
// again, SIGCHLD says CLD_CONTINUED and a WCONTINUED wait reports it
// once. waitid with WNOWAIT leaves a stop to be reported again. A parent
// whose SIGCHLD has SA_NOCLDSTOP is sent none for either. A read blocked
// across a stop and continue goes on and returns its data. SIGKILL ends
// a stopped child. SIGTSTP stops a child in a group of its own under a
// parent of another group of the session, and is discarded in an
// orphaned group (a new session's), where SIGSTOP still stops. A group
// its leader's end orphans with a stopped process in it is sent SIGHUP
// and SIGCONT.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("jobctl: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static void nap(int ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
    }
}

// What is in the pipe now, read without waiting.
static int drain(int fd) {
    char b[4096];
    int n = 0;
    for (;;) {
        long r = read(fd, b, sizeof b);
        if (r <= 0) return n;
        n += r;
    }
}

// The state letter of /proc/<pid>/stat and the State: line's word.
static char state_of(int pid) {
    char path[64], b[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY);
    long n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return '?';
    b[n] = 0;
    char *p = strrchr(b, ')');
    return p && p[1] == ' ' ? p[2] : '?';
}

static int status_says_stopped(int pid) {
    char path[64], b[2048];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    int fd = open(path, O_RDONLY);
    long n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return 0;
    b[n] = 0;
    return strstr(b, "State:\tT (stopped)") != NULL;
}

// The next SIGCHLD (blocked), within ms: its si_code, or -errno.
static int next_chld(int ms, siginfo_t *si) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGCHLD);
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    memset(si, 0, sizeof *si);
    int r = sigtimedwait(&s, si, &ts);
    return r < 0 ? -errno : si->si_code;
}

static int out_fd;

static void *writer(void *arg) {
    (void)arg;
    for (;;) {
        if (write(out_fd, "x", 1) < 0 && errno != EAGAIN) return NULL;
        nap(5);
    }
}

static void stop_and_continue(void) {
    int p[2];
    if (pipe(p) < 0) return;
    int c = fork();
    if (c == 0) {
        close(p[0]);
        out_fd = p[1];
        pthread_t t;
        pthread_create(&t, NULL, writer, NULL);
        writer(NULL);
        _exit(0);
    }
    close(p[1]);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    nap(100);
    want("writes before", drain(p[0]) > 0, 1);

    siginfo_t si;
    int st = 0;
    want("SIGSTOP", kill(c, SIGSTOP), 0);
    want("SIGCHLD for the stop", next_chld(2000, &si), CLD_STOPPED);
    want("its pid", si.si_pid, c);
    want("its status", si.si_status, SIGSTOP);
    want("wait for the stop", waitpid(c, &st, WUNTRACED), c);
    want("stopped", WIFSTOPPED(st), 1);
    want("by", WSTOPSIG(st), SIGSTOP);
    want("raw status", st, 0x137f);
    want("reported once", waitpid(c, &st, WUNTRACED | WNOHANG), 0);
    want("not an end", waitpid(c, &st, WNOHANG), 0);
    want("stat says T", state_of(c), 'T');
    want("status says stopped", status_says_stopped(c), 1);
    drain(p[0]);
    nap(150);
    want("no writes while stopped", drain(p[0]), 0);

    want("SIGCONT", kill(c, SIGCONT), 0);
    want("SIGCHLD for the continue", next_chld(2000, &si), CLD_CONTINUED);
    want("its status", si.si_status, SIGCONT);
    want("wait for the continue", waitpid(c, &st, WCONTINUED), c);
    want("continued", WIFCONTINUED(st), 1);
    want("raw status", st, 0xffff);
    want("continue reported once", waitpid(c, &st, WCONTINUED | WNOHANG), 0);
    nap(150);
    want("writes again", drain(p[0]) > 0, 1);
    want("stat not T", state_of(c) != 'T', 1);

    // waitid, with and without WNOWAIT.
    kill(c, SIGSTOP);
    next_chld(2000, &si);
    memset(&si, 0, sizeof si);
    want("waitid WNOWAIT", waitid(P_PID, c, &si, WSTOPPED | WNOWAIT), 0);
    want("its code", si.si_code, CLD_STOPPED);
    want("its status", si.si_status, SIGSTOP);
    want("its pid", si.si_pid, c);
    memset(&si, 0, sizeof si);
    want("waitid again", waitid(P_PID, c, &si, WSTOPPED), 0);
    want("still there", si.si_code, CLD_STOPPED);
    memset(&si, 0, sizeof si);
    want("then gone", waitid(P_PID, c, &si, WSTOPPED | WNOHANG), 0);
    want("nothing", si.si_pid, 0);
    memset(&si, 0, sizeof si);
    want("waitid WEXITED alone", waitid(P_PID, c, &si, WEXITED | WNOHANG), 0);
    want("finds no stop", si.si_pid, 0);

    // SIGKILL ends it stopped.
    want("SIGKILL", kill(c, SIGKILL), 0);
    want("wait for its end", waitpid(c, &st, 0), c);
    want("killed", WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, 1);
    close(p[0]);
    next_chld(200, &si);
}

static void no_cldstop(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    int c = fork();
    if (c == 0) {
        for (;;) pause();
    }
    siginfo_t si;
    int st;
    kill(c, SIGSTOP);
    want("no-cldstop: wait", waitpid(c, &st, WUNTRACED), c);
    want("no-cldstop: no SIGCHLD for a stop", next_chld(300, &si), -EAGAIN);
    kill(c, SIGCONT);
    want("no-cldstop: wait", waitpid(c, &st, WCONTINUED), c);
    want("no-cldstop: no SIGCHLD for a continue", next_chld(300, &si), -EAGAIN);
    kill(c, SIGKILL);
    waitpid(c, &st, 0);
    want("no-cldstop: SIGCHLD for an end", next_chld(2000, &si), CLD_KILLED);
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, NULL);
}

static void blocked_read(void) {
    int p[2];
    if (pipe(p) < 0) return;
    int c = fork();
    if (c == 0) {
        close(p[1]);
        char b[8];
        long n = read(p[0], b, sizeof b);
        _exit(n < 0 ? 100 + errno : n);
    }
    close(p[0]);
    nap(100);
    int st;
    siginfo_t si;
    kill(c, SIGSTOP);
    want("read: stopped", waitpid(c, &st, WUNTRACED), c);
    want("read: stopped by", WIFSTOPPED(st) ? WSTOPSIG(st) : -1, SIGSTOP);
    kill(c, SIGCONT);
    want("read: continued", waitpid(c, &st, WCONTINUED), c);
    nap(100);
    write(p[1], "abc", 3);
    want("read: its end", waitpid(c, &st, 0), c);
    want("read: what it read", WIFEXITED(st) ? WEXITSTATUS(st) : -1, 3);
    close(p[1]);
    while (next_chld(100, &si) > 0) {
    }
}

static void terminal_stops(void) {
    int st;
    siginfo_t si;
    // In a group of its own, its parent in another group of the session:
    // not orphaned, so SIGTSTP stops it.
    int c = fork();
    if (c == 0) {
        setpgid(0, 0);
        raise(SIGTSTP);
        _exit(5);
    }
    want("tstp: stopped", waitpid(c, &st, WUNTRACED), c);
    want("tstp: by", WIFSTOPPED(st) ? WSTOPSIG(st) : -1, SIGTSTP);
    kill(c, SIGCONT);
    want("tstp: then ends", waitpid(c, &st, 0), c);
    want("tstp: with", WIFEXITED(st) ? WEXITSTATUS(st) : -1, 5);
    // A new session's group is orphaned: SIGTSTP, SIGTTIN and SIGTTOU are
    // discarded, SIGSTOP still stops.
    c = fork();
    if (c == 0) {
        setsid();
        raise(SIGTSTP);
        raise(SIGTTIN);
        raise(SIGTTOU);
        raise(SIGSTOP);
        _exit(7);
    }
    want("orphaned: stopped", waitpid(c, &st, WUNTRACED), c);
    want("orphaned: by SIGSTOP", WIFSTOPPED(st) ? WSTOPSIG(st) : -1, SIGSTOP);
    kill(c, SIGCONT);
    want("orphaned: then ends", waitpid(c, &st, 0), c);
    want("orphaned: with", WIFEXITED(st) ? WEXITSTATUS(st) : -1, 7);
    while (next_chld(100, &si) > 0) {
    }
}

static int hup_fd;
static void on_hup(int s) {
    (void)s;
    write(hup_fd, "H", 1);
}

static void orphaned_by_an_end(void) {
    int p[2];
    if (pipe(p) < 0) return;
    int m = fork();
    if (m == 0) {
        // A group of its own with a child in it, then gone.
        setpgid(0, 0);
        int c = fork();
        if (c == 0) {
            hup_fd = p[1];
            signal(SIGHUP, on_hup);
            raise(SIGSTOP);
            write(p[1], "C", 1);
            _exit(0);
        }
        int st;
        waitpid(c, &st, WUNTRACED);
        _exit(WIFSTOPPED(st) ? 0 : 1);
    }
    close(p[1]);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    int st;
    want("orphaning: its leader", waitpid(m, &st, 0), m);
    want("orphaning: saw the stop", WIFEXITED(st) ? WEXITSTATUS(st) : -1, 0);
    // SIGHUP's handler, then on from the stop.
    char b[4] = {0};
    long n = 0;
    for (int i = 0; i < 40 && n < 2; i++) {
        long r = read(p[0], b + n, sizeof b - 1 - n);
        if (r > 0) n += r;
        else nap(50);
    }
    if (!(n == 2 && b[0] == 'H' && b[1] == 'C')) printf("jobctl: orphaning: read %ld bytes '%s', wanted 'HC'\n", n, b), failed = 1;
    close(p[0]);
}

int main(void) {
    // What a child prints is lost to _exit otherwise.
    setvbuf(stdout, NULL, _IONBF, 0);
    int top = fork();
    if (top == 0) {
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s, SIGCHLD);
        sigprocmask(SIG_BLOCK, &s, NULL);
        stop_and_continue();
        no_cldstop();
        blocked_read();
        terminal_stops();
        orphaned_by_an_end();
        _exit(failed);
    }
    int st;
    waitpid(top, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        printf("jobctl ok\n");
        return 0;
    }
    return 1;
}
