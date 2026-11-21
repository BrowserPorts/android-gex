// How each thread is scheduled, as Linux keeps it: the nice value
// (setpriority, getpriority), the policy and real-time priority
// (sched_setscheduler, sched_setparam, sched_getscheduler,
// sched_getparam), the reset-on-fork flag, what a thread and a child start
// with, /proc/<pid>/task/<tid>/stat's priority, nice, rt_priority and
// policy fields, and who may change what: root (CAP_SYS_NICE) anything, an
// unprivileged process its own nice upwards, downwards and real-time
// priorities only within RLIMIT_NICE and RLIMIT_RTPRIO, and nothing of
// another user's. And the I/O priority (ioprio_set, ioprio_get): read raw
// for a task, derived from nice and policy for a group, copied to a child
// only when it has a class. Run as root; otherwise it exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif
#define SCHED_EXT 7

static int failed;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        if (!(cond)) {                                    \
            printf("sched: line %d: ", __LINE__);         \
            printf(__VA_ARGS__);                          \
            printf(" (errno %d)\n", errno);               \
            failed = 1;                                   \
        }                                                 \
    } while (0)

// The raw calls: getpriority's answer is 20 - nice, and a bad pointer
// reaches the kernel as it is.
static long getprio(int which, int who) { return syscall(SYS_getpriority, which, who); }
static long setprio(int which, int who, int nice) { return syscall(SYS_setpriority, which, who, nice); }
static long setsched(int pid, long policy, struct sched_param *p) { return syscall(SYS_sched_setscheduler, pid, policy, p); }
static long setparam(int pid, struct sched_param *p) { return syscall(SYS_sched_setparam, pid, p); }
static long getsched(int pid) { return syscall(SYS_sched_getscheduler, pid); }
static long getparam(int pid) {
    struct sched_param p = {-1};
    long r = syscall(SYS_sched_getparam, pid, &p);
    return r ? r : p.sched_priority;
}
static long fails(long r) { return r == -1 ? errno : 0; }
static long ioset(int which, int who, int prio) { return syscall(SYS_ioprio_set, which, who, prio); }
static long ioget(int which, int who) { return syscall(SYS_ioprio_get, which, who); }
#define WHO_PROCESS 1
#define WHO_PGRP 2
#define WHO_USER 3
#define IO(class, level) ((class) << 13 | (level))

// Fields 18, 19, 40 and 41 of task `tid`'s stat line: priority, nice,
// rt_priority, policy.
static void stat_fields(pid_t tid, long out[4]) {
    char path[64], buf[1024];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    FILE *f = fopen(path, "r");
    out[0] = out[1] = out[2] = out[3] = -999;
    if (!f) return;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    if (!p) return;
    // field 3 starts after ") "
    int field = 2;
    for (char *t = strtok(p + 1, " "); t; t = strtok(0, " ")) {
        field++;
        if (field == 18) out[0] = atol(t);
        if (field == 19) out[1] = atol(t);
        if (field == 40) out[2] = atol(t);
        if (field == 41) out[3] = atol(t);
    }
}

static pid_t thread_tid;
static long thread_policy, thread_prio, thread_io;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int stage;

static void *thread_main(void *arg) {
    (void)arg;
    thread_tid = gettid();
    thread_policy = getsched(0);
    thread_prio = getparam(0);
    thread_io = ioget(WHO_PROCESS, 0);
    pthread_mutex_lock(&lock);
    stage = 1;
    pthread_cond_broadcast(&cond);
    while (stage != 2) pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
    return 0;
}

// Runs `fn` in a child and fails with what it says.
static void in_child(const char *what, void (*fn)(void)) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        failed = 0;
        fn();
        fflush(stdout);
        _exit(failed);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "%s", what);
}

static void a_reset_child(void) {
    // the parent is SCHED_RR 5 with the flag and nice -5
    CHECK(getsched(0) == SCHED_OTHER, "a reset child's policy %ld", getsched(0));
    CHECK(getparam(0) == 0, "a reset child's priority %ld", getparam(0));
    CHECK(getprio(PRIO_PROCESS, 0) == 20, "a reset child's nice: %ld", 20 - getprio(PRIO_PROCESS, 0));
}

static void a_kept_child(void) {
    CHECK(getsched(0) == SCHED_FIFO, "a child's policy %ld", getsched(0));
    CHECK(getparam(0) == 30, "a child's priority %ld", getparam(0));
    CHECK(ioget(WHO_PROCESS, 0) == IO(2, 6), "a child's I/O priority %#lx", ioget(WHO_PROCESS, 0));
}

static void no_class_child(void) {
    // the parent has class none with a hint: not copied
    CHECK(ioget(WHO_PROCESS, 0) == 0, "a child of class none %#lx", ioget(WHO_PROCESS, 0));
}

// A group's I/O priority where none is set: the scheduling's, best of the
// group (lowest value).
static void io_group(void) {
    setpgid(0, 0);
    CHECK(ioset(WHO_PROCESS, 0, 0) == 0, "none");
    CHECK(setprio(PRIO_PROCESS, 0, 10) == 0, "nice 10");
    CHECK(ioget(WHO_PROCESS, 0) == 0, "raw none");
    CHECK(ioget(WHO_PGRP, 0) == IO(2, 6), "best effort at (10 + 20) / 5: %#lx", ioget(WHO_PGRP, 0));
    int go[2], ready[2];
    if (pipe(go) || pipe(ready)) return;
    pid_t m = fork();
    if (m == 0) {
        setprio(PRIO_PROCESS, 0, 15);
        write(ready[1], "x", 1);
        char c;
        read(go[0], &c, 1);
        _exit(0);
    }
    char c;
    read(ready[0], &c, 1);
    CHECK(ioget(WHO_PGRP, 0) == IO(2, 6), "the best of 6 and 7: %#lx", ioget(WHO_PGRP, 0));
    struct sched_param p = {0};
    CHECK(setsched(0, SCHED_IDLE, &p) == 0, "idle");
    CHECK(ioget(WHO_PGRP, 0) == IO(2, 7), "idle is class 3, the other best effort 7: %#lx", ioget(WHO_PGRP, 0));
    p.sched_priority = 1;
    CHECK(setsched(0, SCHED_FIFO, &p) == 0, "FIFO");
    CHECK(ioget(WHO_PGRP, 0) == IO(1, 6), "real-time class at nice 10's level: %#lx", ioget(WHO_PGRP, 0));
    CHECK(ioset(WHO_PGRP, 0, IO(3, 0)) == 0 && ioget(WHO_PGRP, 0) == IO(3, 0), "set for the group");
    write(go[1], "x", 1);
    waitpid(m, 0, 0);
}

static pid_t root_pid;

static void unprivileged(void) {
    if (setresuid(54321, 54321, 54321)) {
        CHECK(0, "setresuid");
        return;
    }
    struct sched_param p = {1};
    CHECK(fails(setsched(0, SCHED_FIFO, &p)) == EPERM, "an unprivileged FIFO");
    CHECK(setprio(PRIO_PROCESS, 0, 10) == 0, "nice up");
    CHECK(getprio(PRIO_PROCESS, 0) == 10, "nice 10 read back: %ld", getprio(PRIO_PROCESS, 0));
    CHECK(fails(setprio(PRIO_PROCESS, 0, 5)) == EACCES, "nice down without RLIMIT_NICE");
    CHECK(fails(setprio(PRIO_PROCESS, root_pid, 15)) == EPERM, "another user's nice");
    CHECK(getprio(PRIO_PROCESS, root_pid) > 0, "another user's nice read");
    p.sched_priority = 0;
    CHECK(fails(setsched(root_pid, SCHED_OTHER, &p)) == EPERM, "another user's policy");
    CHECK(setsched(0, SCHED_BATCH, &p) == 0, "batch");
    CHECK(setsched(0, SCHED_IDLE, &p) == 0, "idle");
    // leaving SCHED_IDLE is lowering nice from 20
    CHECK(fails(setsched(0, SCHED_OTHER, &p)) == EPERM, "out of idle");
    CHECK(fails(setsched(0, SCHED_BATCH, &p)) == EPERM, "idle to batch");
    CHECK(getsched(0) == SCHED_IDLE, "still idle");
    CHECK(fails(ioset(WHO_PROCESS, 0, IO(1, 0))) == EPERM, "an unprivileged real-time I/O class");
    CHECK(ioset(WHO_PROCESS, 0, IO(3, 0)) == 0 && ioget(WHO_PROCESS, 0) == IO(3, 0), "idle I/O");
    CHECK(fails(ioset(WHO_PROCESS, root_pid, IO(2, 0))) == EPERM, "another user's I/O priority");
}

static void within_limits(void) {
    // as root: room to go to nice -5 and real-time priority 20
    struct rlimit nice = {25, 25}, rt = {20, 20};
    CHECK(setrlimit(RLIMIT_NICE, &nice) == 0 && setrlimit(RLIMIT_RTPRIO, &rt) == 0, "setrlimit");
    if (setresuid(54321, 54321, 54321)) {
        CHECK(0, "setresuid");
        return;
    }
    CHECK(setprio(PRIO_PROCESS, 0, -5) == 0, "nice -5 within RLIMIT_NICE 25");
    CHECK(fails(setprio(PRIO_PROCESS, 0, -6)) == EACCES, "nice -6 past it");
    struct sched_param p = {20};
    CHECK(setsched(0, SCHED_FIFO, &p) == 0, "FIFO 20 within RLIMIT_RTPRIO 20");
    p.sched_priority = 21;
    CHECK(fails(setparam(0, &p)) == EPERM, "21 past it");
    p.sched_priority = 3;
    CHECK(setparam(0, &p) == 0, "down to 3");
    p.sched_priority = 20;
    CHECK(setparam(0, &p) == 0, "back up to 20, within the limit");
    // the flag, once set, is not the unprivileged caller's to clear
    CHECK(setsched(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &p) == 0, "reset on fork");
    CHECK(fails(setsched(0, SCHED_FIFO, &p)) == EPERM, "the flag cleared");
    long f[4];
    stat_fields(getpid(), f);
    CHECK(f[0] == -21 && f[1] == -5 && f[2] == 20 && f[3] == SCHED_FIFO, "stat %ld %ld %ld %ld", f[0], f[1], f[2], f[3]);
}

static void a_group(void) {
    // a group of its own, with a second member
    setpgid(0, 0);
    int go[2];
    if (pipe(go)) return;
    pid_t m = fork();
    if (m == 0) {
        char c;
        read(go[0], &c, 1);
        _exit(getprio(PRIO_PROCESS, 0) == 16 ? 0 : 1);
    }
    CHECK(setprio(PRIO_PGRP, 0, 4) == 0, "by group");
    CHECK(getprio(PRIO_PROCESS, 0) == 16, "the caller in its group: %ld", getprio(PRIO_PROCESS, 0));
    CHECK(getprio(PRIO_PGRP, 0) == 16, "the group's highest");
    CHECK(fails(setprio(PRIO_PGRP, 999999, 4)) == ESRCH, "no such group");
    write(go[1], "x", 1);
    int st;
    waitpid(m, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the other member's nice");
}

static void by_user(void) {
    int go[2], ready[2];
    if (pipe(go) || pipe(ready)) return;
    pid_t u = fork();
    if (u == 0) {
        if (setresuid(54322, 54322, 54322)) _exit(2);
        write(ready[1], "x", 1);
        char c;
        read(go[0], &c, 1);
        _exit(getprio(PRIO_PROCESS, 0) == 14 ? 0 : 1);
    }
    char c;
    read(ready[0], &c, 1);
    CHECK(setprio(PRIO_USER, 54322, 6) == 0, "by user");
    CHECK(getprio(PRIO_USER, 54322) == 14, "the user's highest: %ld", getprio(PRIO_USER, 54322));
    CHECK(fails(getprio(PRIO_USER, 54323)) == ESRCH, "a user with no processes");
    write(go[1], "x", 1);
    int st;
    waitpid(u, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the user's process's nice");
}

int main(void) {
    if (geteuid() != 0) {
        printf("sched: needs root\n");
        return 77;
    }
    root_pid = getpid();
    // From a known start: nice 0, SCHED_OTHER.
    struct sched_param p = {0};
    setprio(PRIO_PROCESS, 0, 0);
    sched_setscheduler(0, SCHED_OTHER, &p);

    // The bounds of each policy.
    CHECK(sched_get_priority_max(SCHED_FIFO) == 99 && sched_get_priority_min(SCHED_RR) == 1, "rt bounds");
    CHECK(sched_get_priority_max(SCHED_OTHER) == 0 && sched_get_priority_min(SCHED_BATCH) == 0, "other bounds");
    CHECK(sched_get_priority_max(SCHED_DEADLINE) == 0 && sched_get_priority_max(SCHED_EXT) == 0, "deadline and ext bounds");
    CHECK(sched_get_priority_max(4) == -1 && errno == EINVAL, "policy 4");
    CHECK(sched_get_priority_min(-1) == -1 && errno == EINVAL, "policy -1");

    // Defaults.
    CHECK(getsched(0) == SCHED_OTHER && getparam(0) == 0, "the start");
    CHECK(getprio(PRIO_PROCESS, 0) == 20, "nice 0");
    long f[4];
    stat_fields(getpid(), f);
    CHECK(f[0] == 20 && f[1] == 0 && f[2] == 0 && f[3] == 0, "stat at the start: %ld %ld %ld %ld", f[0], f[1], f[2], f[3]);

    // What is refused, whoever asks.
    p.sched_priority = 0;
    CHECK(fails(setsched(0, SCHED_FIFO, &p)) == EINVAL, "FIFO at 0");
    p.sched_priority = 1;
    CHECK(fails(setsched(0, SCHED_OTHER, &p)) == EINVAL, "OTHER at 1");
    p.sched_priority = 100;
    CHECK(fails(setsched(0, SCHED_RR, &p)) == EINVAL, "RR at 100");
    p.sched_priority = -1;
    CHECK(fails(setsched(0, SCHED_RR, &p)) == EINVAL, "RR at -1");
    p.sched_priority = 0;
    CHECK(fails(setsched(0, 4, &p)) == EINVAL, "policy 4");
    CHECK(fails(setsched(0, SCHED_DEADLINE, &p)) == EINVAL, "deadline without its parameters");
    CHECK(fails(setsched(0, 0x10000000, &p)) == EINVAL, "a policy with another high bit");
    CHECK(fails(setsched(0, -1, &p)) == EINVAL, "policy -1");
    CHECK(fails(setsched(-1, SCHED_OTHER, &p)) == EINVAL, "pid -1");
    CHECK(fails(setsched(0, SCHED_OTHER, 0)) == EINVAL, "no param");
    CHECK(fails(setsched(0, SCHED_OTHER, (void *)8)) == EFAULT, "a bad param");
    CHECK(fails(getsched(-1)) == EINVAL, "getscheduler of -1");
    CHECK(fails(syscall(SYS_sched_getparam, 0, 0)) == EINVAL, "getparam into nothing");
    CHECK(fails(setprio(3, 0, 0)) == EINVAL && fails(getprio(-1, 0)) == EINVAL, "which out of range");
    // a reaped child's pid names nothing
    pid_t gone = fork();
    if (gone == 0) _exit(0);
    waitpid(gone, 0, 0);
    CHECK(fails(getsched(gone)) == ESRCH && fails(getprio(PRIO_PROCESS, gone)) == ESRCH, "a reaped child");
    CHECK(fails(setsched(gone, SCHED_OTHER, &p)) == ESRCH, "setscheduler of a reaped child");

    // The ext policy is a fair one; root takes SCHED_FIFO, and its
    // priority and nice are kept apart.
    CHECK(setsched(0, SCHED_EXT, &p) == 0 && getsched(0) == SCHED_EXT, "ext");
    CHECK(setsched(0, SCHED_BATCH, &p) == 0 && getsched(0) == SCHED_BATCH, "batch");
    CHECK(setprio(PRIO_PROCESS, 0, -5) == 0, "root's nice -5");
    p.sched_priority = 10;
    CHECK(setsched(0, SCHED_FIFO, &p) == 0, "root's FIFO");
    CHECK(getsched(0) == SCHED_FIFO && getparam(0) == 10, "FIFO 10 read back");
    CHECK(getprio(PRIO_PROCESS, 0) == 25, "nice kept under FIFO: %ld", getprio(PRIO_PROCESS, 0));
    stat_fields(getpid(), f);
    CHECK(f[0] == -11 && f[1] == -5 && f[2] == 10 && f[3] == SCHED_FIFO, "stat under FIFO: %ld %ld %ld %ld", f[0], f[1], f[2], f[3]);
    p.sched_priority = 30;
    CHECK(setparam(0, &p) == 0 && getsched(0) == SCHED_FIFO && getparam(0) == 30, "setparam keeps the policy");

    // The I/O priority: raw for a task, checked by class first.
    CHECK(ioset(WHO_PROCESS, 0, 0) == 0 && ioget(WHO_PROCESS, 0) == 0, "I/O class none");
    CHECK(fails(ioset(WHO_PROCESS, 0, 1)) == EINVAL, "class none at level 1");
    CHECK(fails(ioset(WHO_PROCESS, 0, IO(4, 0))) == EINVAL, "I/O class 4");
    CHECK(fails(ioset(4, 0, IO(2, 0))) == EINVAL && fails(ioget(0, 0)) == EINVAL, "which out of range");
    CHECK(fails(ioset(WHO_PROCESS, gone, IO(2, 0))) == ESRCH && fails(ioget(WHO_PROCESS, gone)) == ESRCH, "I/O of a reaped child");
    CHECK(fails(ioset(WHO_USER, -1, IO(2, 0))) == ESRCH, "no uid -1");
    // kept as an unsigned short: 0x12006's class is bits 13 to 15, 1
    CHECK(ioset(WHO_PROCESS, 0, 0x12006) == 0 && ioget(WHO_PROCESS, 0) == 0x2006, "truncated: %#lx", ioget(WHO_PROCESS, 0));
    CHECK(ioset(WHO_PROCESS, 0, IO(2, 6)) == 0 && ioget(WHO_PROCESS, 0) == IO(2, 6), "best effort 6");

    // A thread starts with its creator's; its own nice is its own.
    pthread_t t;
    pthread_create(&t, 0, thread_main, 0);
    pthread_mutex_lock(&lock);
    while (stage != 1) pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
    CHECK(thread_policy == SCHED_FIFO && thread_prio == 30, "a thread's start: %ld %ld", thread_policy, thread_prio);
    CHECK(thread_io == IO(2, 6), "a thread's I/O priority %#lx", thread_io);
    CHECK(setprio(PRIO_PROCESS, thread_tid, 7) == 0, "a thread's nice by its id");
    CHECK(getprio(PRIO_PROCESS, thread_tid) == 13 && getprio(PRIO_PROCESS, 0) == 25, "the thread's alone");
    p.sched_priority = 0;
    CHECK(setsched(thread_tid, SCHED_OTHER, &p) == 0 && getsched(thread_tid) == SCHED_OTHER && getsched(0) == SCHED_FIFO, "a thread's policy alone");
    stat_fields(thread_tid, f);
    CHECK(f[0] == 27 && f[1] == 7 && f[2] == 0 && f[3] == SCHED_OTHER, "the thread's stat: %ld %ld %ld %ld", f[0], f[1], f[2], f[3]);
    pthread_mutex_lock(&lock);
    stage = 2;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    pthread_join(t, 0);

    // A child starts with its parent's, unless the parent asked for the
    // reset: then policy and negative nice go back to the default.
    in_child("a child keeps FIFO", a_kept_child);
    p.sched_priority = 5;
    CHECK(setsched(0, SCHED_RR | SCHED_RESET_ON_FORK, &p) == 0, "RR with the reset");
    CHECK(getsched(0) == (SCHED_RR | SCHED_RESET_ON_FORK), "the flag read back: %#lx", getsched(0));
    CHECK(setparam(0, &p) == 0 && getsched(0) == (SCHED_RR | SCHED_RESET_ON_FORK), "setparam keeps the flag");
    in_child("a reset child", a_reset_child);
    CHECK(ioset(WHO_PROCESS, 0, 8) == 0 && ioget(WHO_PROCESS, 0) == 8, "class none with a hint");
    in_child("a child of class none", no_class_child);
    CHECK(ioset(WHO_PROCESS, 0, 0) == 0, "I/O priority back to none");
    p.sched_priority = 0;
    CHECK(setsched(0, SCHED_OTHER, &p) == 0 && getsched(0) == SCHED_OTHER, "root clears the flag");
    CHECK(setprio(PRIO_PROCESS, 0, 0) == 0, "root's nice back to 0");

    // Without CAP_SYS_NICE.
    in_child("an unprivileged process", unprivileged);
    in_child("an unprivileged process within its limits", within_limits);
    // By process group and by user.
    in_child("a process group", a_group);
    in_child("a group's I/O priority", io_group);
    by_user();

    if (failed) return 1;
    printf("sched ok\n");
    return 0;
}
