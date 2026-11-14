// rt_sigqueueinfo and rt_tgsigqueueinfo: sigqueue's value and code reach
// the handler, to the process and to one thread of it; a code that claims
// to be the kernel's or kill's is refused to anyone but the sender itself;
// and abort, which bionic raises this way, kills with SIGABRT.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                          \
    do {                                                  \
        if (!(c)) {                                       \
            printf("%s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                     \
        }                                                 \
    } while (0)

static volatile sig_atomic_t got_code, got_value, got_pid, got_tid, hits;

static void on_signal(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    got_code = si->si_code;
    got_value = si->si_value.sival_int;
    got_pid = si->si_pid;
    got_tid = gettid();
    hits++;
}

static volatile int ready, done;
static void *waiter(void *arg) {
    *(pid_t *)arg = gettid();
    ready = 1;
    while (!done) usleep(1000);
    return 0;
}

int main(void) {
    struct sigaction sa = {.sa_sigaction = on_signal, .sa_flags = SA_SIGINFO};
    CHECK(sigaction(SIGUSR1, &sa, 0) == 0);

    CHECK(sigqueue(getpid(), SIGUSR1, (union sigval){.sival_int = 4242}) == 0);
    CHECK(hits == 1 && got_code == SI_QUEUE && got_value == 4242 && got_pid == getpid());

    // To one thread: it is the one that runs the handler.
    pthread_t t;
    pid_t tid = 0;
    CHECK(pthread_create(&t, 0, waiter, &tid) == 0);
    while (!ready) usleep(1000);
    siginfo_t info;
    memset(&info, 0, sizeof info);
    info.si_signo = SIGUSR1;
    info.si_code = SI_QUEUE;
    info.si_pid = getpid();
    info.si_uid = getuid();
    info.si_value.sival_int = 77;
    CHECK(syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, SIGUSR1, &info) == 0);
    for (int i = 0; i < 2000 && hits < 2; i++) usleep(1000);
    CHECK(hits == 2 && got_tid == tid && got_value == 77 && got_code == SI_QUEUE);
    done = 1;
    pthread_join(t, 0);

    // The caller may give itself any code; arguments are checked.
    info.si_code = SI_USER;
    info.si_value.sival_int = 5;
    CHECK(syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGUSR1, &info) == 0);
    CHECK(hits == 3 && got_code == SI_USER);
    CHECK(syscall(SYS_rt_tgsigqueueinfo, getpid(), 0, SIGUSR1, &info) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGUSR1, -4096L) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_rt_sigqueueinfo, getpid(), 1000, &info) == -1 && errno == EINVAL);

    // Another process is not told a signal is kill's; SI_QUEUE it may be.
    fflush(stdout);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        for (int i = 0; i < 5000 && hits < 4; i++) usleep(1000);
        _exit(hits == 4 ? 0 : 3);
    }
    info.si_code = SI_USER;
    CHECK(syscall(SYS_rt_sigqueueinfo, child, SIGUSR1, &info) == -1 && errno == EPERM);
    info.si_code = SI_TKILL;
    CHECK(syscall(SYS_rt_sigqueueinfo, child, SIGUSR1, &info) == -1 && errno == EPERM);
    info.si_code = SI_QUEUE;
    CHECK(syscall(SYS_rt_sigqueueinfo, child, SIGUSR1, &info) == 0);
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    // abort.
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct sigaction dfl = {.sa_handler = SIG_DFL};
        sigaction(SIGABRT, &dfl, 0);
        abort();
    }
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);

    printf("sigqueue ok\n");
    return 0;
}
