// PR_SET_PDEATHSIG: a process is sent the signal it named when its parent
// ends, from the parent; the setting reads back, a child starts without
// it, and it survives an exec.
//
// PR_SET_CHILD_SUBREAPER: a process that asks for it is given its
// descendants' orphans. A grandchild whose parent ends has the subreaper
// for a parent from then on, the subreaper is the one that collects it, and
// a child of the subreaper does not have the setting itself.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t got, from;

static void on_term(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    (void)ctx;
    got = 1;
    from = si->si_pid;
}

// The grandchild of the death-signal test, as the program it execs: waits
// for the signal and says through `fd` who sent it and what its setting is.
static int exec_side(int fd) {
    struct sigaction sa = {.sa_sigaction = on_term, .sa_flags = SA_SIGINFO};
    sigaction(SIGTERM, &sa, 0);
    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGTERM);
    int set = -1;
    prctl(PR_GET_PDEATHSIG, &set);
    // The signal may be pending already: it was blocked across the exec.
    sigprocmask(SIG_UNBLOCK, &unblock, 0);
    for (int i = 0; i < 500 && !got; i++) usleep(10000);
    int out[3] = {got, from, set};
    return write(fd, out, sizeof out) == sizeof out ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "exec-side")) return exec_side(argv[2][0] - '0');
    int status = 0;

    // The death signal. A middle process makes a grandchild and ends; the
    // grandchild named SIGTERM for that, and execs to wait for it.
    int p[2], ready[2];
    if (pipe(p) || pipe(ready)) return 2;
    pid_t middle = fork();
    if (middle == 0) {
        pid_t me = getpid();
        if (fork() == 0) {
            int set = -1;
            // None to begin with, though the parent set one below? No: the
            // parent set none; and what is set reads back.
            if (prctl(PR_GET_PDEATHSIG, &set) || set != 0) _exit(10);
            if (prctl(PR_SET_PDEATHSIG, 65) != -1 || errno != EINVAL) _exit(11);
            sigset_t block;
            sigemptyset(&block);
            sigaddset(&block, SIGTERM);
            sigprocmask(SIG_BLOCK, &block, 0);
            if (prctl(PR_SET_PDEATHSIG, SIGTERM)) _exit(12);
            if (prctl(PR_GET_PDEATHSIG, &set) || set != SIGTERM) _exit(13);
            // A child of this one starts with none.
            pid_t c = fork();
            if (c == 0) {
                int s2 = -1;
                _exit(prctl(PR_GET_PDEATHSIG, &s2) || s2 != 0 ? 1 : 0);
            }
            int st;
            if (waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st)) _exit(14);
            // Tell the middle process it may end, and who it is.
            if (write(ready[1], &me, sizeof me) != sizeof me) _exit(15);
            char fd[2] = {(char)('0' + p[1]), 0};
            char *args[] = {argv[0], "exec-side", fd, 0};
            execv(argv[0], args);
            _exit(16);
        }
        // End once the grandchild has set its signal.
        pid_t who;
        if (read(ready[0], &who, sizeof who) != sizeof who) _exit(1);
        _exit(0);
    }
    int st;
    if (waitpid(middle, &st, 0) != middle || !WIFEXITED(st) || WEXITSTATUS(st)) status |= 1;
    int out[3] = {0, 0, 0};
    close(p[1]);
    if (read(p[0], out, sizeof out) != sizeof out) status |= 2;
    // Signalled, by the middle process, and the setting was still SIGTERM
    // after the exec.
    if (out[0] != 1 || out[1] != middle || out[2] != SIGTERM) {
        printf("pdeath: signalled %d by %d (the parent was %d), setting %d\n", out[0], out[1], (int)middle, out[2]);
        status |= 4;
    }

    // The subreaper. Off to begin with; any value but 0 turns it on.
    int sub = -1;
    if (prctl(PR_GET_CHILD_SUBREAPER, &sub) || sub != 0) status |= 8;
    if (prctl(PR_SET_CHILD_SUBREAPER, 5) || prctl(PR_GET_CHILD_SUBREAPER, &sub) || sub != 1) status |= 8;
    int q[2], go[2];
    if (pipe(q) || pipe(go)) return 2;
    middle = fork();
    if (middle == 0) {
        // Not inherited.
        int s3 = -1;
        if (prctl(PR_GET_CHILD_SUBREAPER, &s3) || s3 != 0) _exit(20);
        pid_t orphan = fork();
        if (orphan == 0) {
            // Wait until the middle process is gone, then say who the
            // parent is now.
            char c;
            if (read(go[0], &c, 1) != 1) _exit(1);
            pid_t parent = getppid();
            _exit(write(q[1], &parent, sizeof parent) == sizeof parent ? 7 : 1);
        }
        if (write(q[1], &orphan, sizeof orphan) != sizeof orphan) _exit(21);
        _exit(0);
    }
    pid_t orphan = 0, parent = 0;
    if (read(q[0], &orphan, sizeof orphan) != sizeof orphan) status |= 16;
    if (waitpid(middle, &st, 0) != middle || !WIFEXITED(st) || WEXITSTATUS(st)) status |= 16;
    if (write(go[1], "g", 1) != 1) status |= 16;
    if (read(q[0], &parent, sizeof parent) != sizeof parent || parent != getpid()) status |= 32;
    // And it is this process that collects the orphan.
    if (waitpid(orphan, &st, 0) != orphan || !WIFEXITED(st) || WEXITSTATUS(st) != 7) status |= 64;
    prctl(PR_SET_CHILD_SUBREAPER, 0);
    if (prctl(PR_GET_CHILD_SUBREAPER, &sub) || sub != 0) status |= 8;

    if (status) {
        printf("pdeath %d\n", status);
        return 1;
    }
    printf("pdeath ok\n");
    return 0;
}
