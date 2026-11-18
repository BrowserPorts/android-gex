// seccomp, as Android's minijail and zygote use it: filters checked when
// installed, their actions (allow, errno, trap, trace with no tracer, log,
// kill the thread, kill the process), the newest of equal actions winning,
// filters kept across clone, fork and exec, TSYNC, strict mode, and what
// prctl and /proc/self/status say. Prints each answer and checks them
// against Linux 7.0's. As an ordinary user.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "mode at start: 0, status 0 0\n"
    "action 0x80000000 available: 0\n"
    "action 0 available: 0\n"
    "action 0x30000 available: 0\n"
    "action 0x50000 available: 0\n"
    "action 0x7fc00000 available: 0\n"
    "action 0x7ff00000 available: 0\n"
    "action 0x7ffc0000 available: 0\n"
    "action 0x7fff0000 available: 0\n"
    "action 0x70000 available: -95\n"
    "action 0x50005 available: -95\n"
    "action avail with flags: -22\n"
    "notif sizes: 0 80 24 64\n"
    "unknown op: -22\n"
    "strict: signal 9\n"
    "strict then prctl: signal 9\n"
    "filter without no_new_privs: -13\n"
    "no_new_privs: 0\n"
    "empty: -22\n"
    "4097 instructions: -22\n"
    "bad pointer: -14\n"
    "bad instructions pointer: -14\n"
    "unknown flag: -22\n"
    "no return at the end: -22\n"
    "load past the data: -22\n"
    "misaligned load: -22\n"
    "byte load: -22\n"
    "jump past the end: -22\n"
    "memory read before written: -22\n"
    "division by zero: -22\n"
    "memory slot 16: -22\n"
    "still mode 0 after refusals\n"
    "errno filter: 0\n"
    "getppid: -77\n"
    "mode 2, status 2 1\n"
    "errno 5000 filter: 0\n"
    "getsid: -4095\n"
    "len filter: 0\n"
    "getppid, newest of equal actions: -30\n"
    "errno 6 filter: 0\n"
    "errno 5 filter: 0\n"
    "getpgid: -5\n"
    "trap filter on gettid: 0\n"
    "allow filter: 0\n"
    "trapped gettid returned 4242; code 1 errno 9 call 1 arch 1 addr 1\n"
    "trace filter: 0\n"
    "getuid: -38\n"
    "log filter: 0\n"
    "getgid made: 1\n"
    "argument filter: 0\n"
    "getpriority(77): -11, getpriority(0): 1\n"
    "new thread's getpgid: -5\n"
    "forked child's getppid: 30\n"
    "thread killed: 1; this one's getpgid(999999) after: -5\n"
    "kill process: signal 31\n"
    "unknown action: signal 31\n"
    "tsync: 0\n"
    "sibling's getppid after tsync: -21\n"
    "tsync with a sibling of its own: a thread id\n"
    "the same with TSYNC_ESRCH: -3\n"
    "getppid here: -21\n"
    "exec child: exit 21\n";

static char out_buf[8192];
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

#define NR_OFF offsetof(struct seccomp_data, nr)
#define ARCH_OFF offsetof(struct seccomp_data, arch)
#define ARG0_OFF offsetof(struct seccomp_data, args[0])

static long sc(unsigned op, unsigned flags, void *arg) {
    return syscall(__NR_seccomp, op, flags, arg);
}

// The call's result, or minus its errno.
static long res(long r) {
    return r < 0 ? -errno : r;
}

static long install(struct sock_filter *f, unsigned short len, unsigned flags) {
    struct sock_fprog p = {len, f};
    return res(sc(SECCOMP_SET_MODE_FILTER, flags, &p));
}

// A filter that answers `ret` for system call `nr` and allows the rest.
static long on_call(int nr, unsigned ret, unsigned flags) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, NR_OFF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, ret),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    return install(f, 4, flags);
}

static long status_field(const char *name) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = -1;
    size_t n = strlen(name);
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, name, n) && line[n] == ':') {
            v = strtol(line + n + 1, NULL, 10);
            break;
        }
    if (f)
        fclose(f);
    return v;
}

static volatile int trap_code, trap_errno, trap_call, trap_arch, trap_addr;

static void on_sigsys(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    trap_code = si->si_code;
    trap_errno = si->si_errno;
    trap_call = si->si_syscall;
    trap_arch = si->si_arch == AUDIT_ARCH_AARCH64;
    trap_addr = si->si_call_addr != NULL;
}

static void *call_getpgid(void *arg) {
    (void)arg;
    long r = res(syscall(__NR_getpgid, 999999));
    return (void *)r;
}

static void *filter_self_then_call(void *arg) {
    (void)arg;
    on_call(__NR_getpgid, SECCOMP_RET_KILL_THREAD, 0);
    syscall(__NR_getpgid, 999999);
    return (void *)1;  // not reached
}

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int stage;

static void wait_stage(int s) {
    pthread_mutex_lock(&gate);
    while (stage < s)
        pthread_cond_wait(&cond, &gate);
    pthread_mutex_unlock(&gate);
}

static void set_stage(int s) {
    pthread_mutex_lock(&gate);
    stage = s;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&gate);
}

// A thread that waits, (2) adds a filter of its own if asked, then waits
// to be told to call getppid and says what it got.
static long sibling_answer;
static int sibling_filters;

static void *sibling(void *arg) {
    (void)arg;
    wait_stage(1);
    if (sibling_filters)
        on_call(__NR_getsid, SECCOMP_RET_ERRNO | 3, 0);
    set_stage(2);
    wait_stage(3);
    sibling_answer = res(syscall(__NR_getppid));
    return NULL;
}

// Run `f` in a forked child; its end: "exit N" or "signal N".
static void in_child(const char *what, void (*f)(void)) {
    pid_t p = fork();
    if (p == 0) {
        f();
        _exit(0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (WIFSIGNALED(st))
        SAY("%s: signal %d\n", what, WTERMSIG(st));
    else
        SAY("%s: exit %d\n", what, WEXITSTATUS(st));
}

static void kill_process_child(void) {
    // Two threads, so that the process is killed and not just the thread.
    pthread_t t;
    pthread_create(&t, NULL, call_getpgid, NULL);
    pthread_join(t, NULL);
    on_call(__NR_getpgid, SECCOMP_RET_KILL_PROCESS, 0);
    syscall(__NR_getpgid, 999999);
    _exit(5);
}

static void unknown_action_child(void) {
    on_call(__NR_sched_yield, 0x00070000, 0);
    syscall(__NR_sched_yield);
    _exit(5);
}

static void strict_child(void) {
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
        _exit(6);
    const char msg[] = "strict: write allowed\n";
    syscall(__NR_write, 1, msg, sizeof msg - 1);
    syscall(__NR_getpid);
    syscall(__NR_exit, 7);
}

static void strict_then_filter_child(void) {
    // A filter is refused once in strict mode: and prctl itself is not
    // one of the four calls, so this ends the process.
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
        _exit(6);
    prctl(PR_GET_SECCOMP);
    syscall(__NR_exit, 7);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "after-exec")) {
        // The filters are kept across execve: the answer, the mode and
        // the count, as an exit status.
        return res(syscall(__NR_getppid)) == -21 && prctl(PR_GET_SECCOMP) == 2 && status_field("Seccomp_filters") == 11 ? 21 : 99;
    }
    SAY("mode at start: %d, status %ld %ld\n", prctl(PR_GET_SECCOMP), status_field("Seccomp"), status_field("Seccomp_filters"));

    // What the kernel says it has.
    unsigned actions[] = {SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP, SECCOMP_RET_ERRNO,
                          SECCOMP_RET_USER_NOTIF, SECCOMP_RET_TRACE, SECCOMP_RET_LOG, SECCOMP_RET_ALLOW,
                          0x00070000, SECCOMP_RET_ERRNO | 5};
    for (unsigned i = 0; i < sizeof actions / sizeof *actions; i++)
        SAY("action %#x available: %ld\n", actions[i], res(sc(SECCOMP_GET_ACTION_AVAIL, 0, &actions[i])));
    SAY("action avail with flags: %ld\n", res(sc(SECCOMP_GET_ACTION_AVAIL, 1, &actions[0])));
    struct seccomp_notif_sizes sizes = {0};
    SAY("notif sizes: %ld %u %u %u\n", res(sc(SECCOMP_GET_NOTIF_SIZES, 0, &sizes)), sizes.seccomp_notif,
        sizes.seccomp_notif_resp, sizes.seccomp_data);
    SAY("unknown op: %ld\n", res(sc(9, 0, NULL)));

    // Strict mode, before any filter (a filter rules it out).
    in_child("strict", strict_child);
    in_child("strict then prctl", strict_then_filter_child);

    // Not allowed without no_new_privs (or CAP_SYS_ADMIN).
    SAY("filter without no_new_privs: %ld\n", on_call(__NR_getppid, SECCOMP_RET_ALLOW, 0));
    SAY("no_new_privs: %d\n", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

    // Filters the kernel refuses.
    struct sock_filter ok[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    SAY("empty: %ld\n", install(ok, 0, 0));
    struct sock_filter *big = calloc(4097, sizeof *big);
    for (int i = 0; i < 4097; i++)
        big[i] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    SAY("4097 instructions: %ld\n", install(big, 4097, 0));
    SAY("bad pointer: %ld\n", res(sc(SECCOMP_SET_MODE_FILTER, 0, (void *)8)));
    struct sock_fprog nullprog = {1, (struct sock_filter *)8};
    SAY("bad instructions pointer: %ld\n", res(sc(SECCOMP_SET_MODE_FILTER, 0, &nullprog)));
    SAY("unknown flag: %ld\n", install(ok, 1, 0x80));
    struct sock_filter no_ret[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, NR_OFF)};
    SAY("no return at the end: %ld\n", install(no_ret, 1, 0));
    struct sock_filter past[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 64), BPF_STMT(BPF_RET | BPF_A, 0)};
    SAY("load past the data: %ld\n", install(past, 2, 0));
    struct sock_filter misaligned[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 2), BPF_STMT(BPF_RET | BPF_A, 0)};
    SAY("misaligned load: %ld\n", install(misaligned, 2, 0));
    struct sock_filter byte[] = {BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0), BPF_STMT(BPF_RET | BPF_A, 0)};
    SAY("byte load: %ld\n", install(byte, 2, 0));
    struct sock_filter far[] = {BPF_JUMP(BPF_JMP | BPF_JA, 5, 0, 0), BPF_STMT(BPF_RET | BPF_K, 0)};
    SAY("jump past the end: %ld\n", install(far, 2, 0));
    struct sock_filter unset[] = {BPF_STMT(BPF_LD | BPF_MEM, 3), BPF_STMT(BPF_RET | BPF_A, 0)};
    SAY("memory read before written: %ld\n", install(unset, 2, 0));
    struct sock_filter div0[] = {BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 0), BPF_STMT(BPF_RET | BPF_A, 0)};
    SAY("division by zero: %ld\n", install(div0, 2, 0));
    struct sock_filter slot16[] = {BPF_STMT(BPF_ST, 16), BPF_STMT(BPF_RET | BPF_K, 0)};
    SAY("memory slot 16: %ld\n", install(slot16, 2, 0));
    // getppid's answer made from len (64), the scratch memory and X:
    // ERRNO with data 30.
    struct sock_filter ld_len[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, NR_OFF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 6),
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
        BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, (SECCOMP_RET_ERRNO | 30) - 64),
        BPF_STMT(BPF_ST, 0),
        BPF_STMT(BPF_LDX | BPF_MEM, 0),
        BPF_STMT(BPF_MISC | BPF_TXA, 0),
        BPF_STMT(BPF_RET | BPF_A, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    SAY("still mode %d after refusals\n", prctl(PR_GET_SECCOMP));

    // ERRNO, its data capped at 4095; the arithmetic, memory and len.
    SAY("errno filter: %ld\n", on_call(__NR_getppid, SECCOMP_RET_ERRNO | 77, 0));
    SAY("getppid: %ld\n", res(syscall(__NR_getppid)));
    SAY("mode %d, status %ld %ld\n", prctl(PR_GET_SECCOMP), status_field("Seccomp"), status_field("Seccomp_filters"));
    SAY("errno 5000 filter: %ld\n", on_call(__NR_getsid, SECCOMP_RET_ERRNO | 5000, 0));
    SAY("getsid: %ld\n", res(syscall(__NR_getsid, 0)));
    SAY("len filter: %ld\n", install(ld_len, 9, 0));
    SAY("getppid, newest of equal actions: %ld\n", res(syscall(__NR_getppid)));

    // Newest first among equals; the lower action wins over the newer.
    SAY("errno 6 filter: %ld\n", on_call(__NR_getpgid, SECCOMP_RET_ERRNO | 6, 0));
    SAY("errno 5 filter: %ld\n", on_call(__NR_getpgid, SECCOMP_RET_ERRNO | 5, 0));
    SAY("getpgid: %ld\n", res(syscall(__NR_getpgid, 0)));
    SAY("trap filter on gettid: %ld\n", on_call(__NR_gettid, SECCOMP_RET_TRAP | 9, 0));
    SAY("allow filter: %ld\n", on_call(__NR_gettid, SECCOMP_RET_ALLOW, 0));

    // TRAP: SIGSYS with the call's details; the call's first argument is
    // what the call returns.
    struct sigaction sa = {0};
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, NULL);
    long t = syscall(__NR_gettid, 4242);
    SAY("trapped gettid returned %ld; code %d errno %d call %d arch %d addr %d\n", t, trap_code, trap_errno,
        trap_call == __NR_gettid, trap_arch, trap_addr);

    // TRACE with no tracer: ENOSYS. LOG: the call is made.
    SAY("trace filter: %ld\n", on_call(__NR_getuid, SECCOMP_RET_TRACE | 1, 0));
    SAY("getuid: %ld\n", res(syscall(__NR_getuid)) == -ENOSYS ? (long)-ENOSYS : 0L);
    SAY("log filter: %ld\n", on_call(__NR_getgid, SECCOMP_RET_LOG, 0));
    SAY("getgid made: %d\n", res(syscall(__NR_getgid)) == (long)getegid() || res(syscall(__NR_getgid)) >= 0);

    // Arguments and the architecture.
    struct sock_filter by_arg[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARCH_OFF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, NR_OFF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpriority, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG0_OFF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 77, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 11),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    SAY("argument filter: %ld\n", install(by_arg, 9, 0));
    SAY("getpriority(77): %ld, getpriority(0): %d\n", res(syscall(__NR_getpriority, 77, 0)),
        res(syscall(__NR_getpriority, 0, 0)) >= 0);

    // A thread made now has them; a forked child has them.
    pthread_t th;
    void *r = NULL;
    pthread_create(&th, NULL, call_getpgid, NULL);
    pthread_join(th, &r);
    SAY("new thread's getpgid: %ld\n", (long)r);
    pid_t p = fork();
    if (p == 0) {
        _exit((int)-res(syscall(__NR_getppid)));
    }
    int st = 0;
    waitpid(p, &st, 0);
    SAY("forked child's getppid: %d\n", WEXITSTATUS(st));

    // KILL_THREAD ends the thread alone.
    pthread_create(&th, NULL, filter_self_then_call, NULL);
    r = NULL;
    pthread_join(th, &r);
    SAY("thread killed: %d; this one's getpgid(999999) after: %ld\n", r == NULL, res(syscall(__NR_getpgid, 999999)));

    // KILL_PROCESS, and an unknown action, end the process.
    in_child("kill process", kill_process_child);
    in_child("unknown action", unknown_action_child);

    // TSYNC: a sibling with no filters of its own takes the new one; one
    // with a filter of its own is in the way, and its id is the answer.
    sibling_filters = 0;
    stage = 0;
    pthread_create(&th, NULL, sibling, NULL);
    set_stage(1);
    wait_stage(2);
    SAY("tsync: %ld\n", on_call(__NR_getppid, SECCOMP_RET_ERRNO | 21, SECCOMP_FILTER_FLAG_TSYNC));
    set_stage(3);
    pthread_join(th, NULL);
    SAY("sibling's getppid after tsync: %ld\n", sibling_answer);
    sibling_filters = 1;
    stage = 0;
    pthread_create(&th, NULL, sibling, NULL);
    set_stage(1);
    wait_stage(2);
    long tr = on_call(__NR_getppid, SECCOMP_RET_ERRNO | 22, SECCOMP_FILTER_FLAG_TSYNC);
    SAY("tsync with a sibling of its own: %s\n", tr > 0 ? "a thread id" : tr == 0 ? "0" : "an error");
    long te = on_call(__NR_getppid, SECCOMP_RET_ERRNO | 22, SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH);
    SAY("the same with TSYNC_ESRCH: %ld\n", te);
    set_stage(3);
    pthread_join(th, NULL);
    SAY("getppid here: %ld\n", res(syscall(__NR_getppid)));

    // Kept across execve.
    fflush(stdout);
    p = fork();
    if (p == 0) {
        char *args[] = {argv[0], "after-exec", NULL};
        execv("/proc/self/exe", args);
        _exit(9);
    }
    waitpid(p, &st, 0);
    SAY("exec child: exit %d\n", WEXITSTATUS(st));

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("seccomp: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "seccomp ok\n" : "seccomp done\n");
    return 0;
}
