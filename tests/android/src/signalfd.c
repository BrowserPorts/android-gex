// signalfd: signals read from a descriptor, as Android's init takes
// SIGCHLD and SIGTERM on the epoll set it waits on.
//
// - A read takes the pending signals of the descriptor's mask, each a
//   signalfd_siginfo with its number, how it was sent and by whom: the
//   reading thread's own first, then its process's, lowest number first
//   in each. With none it is EAGAIN, or waits; a buffer too small for one
//   is EINVAL. Signals not in the mask stay pending.
// - poll and epoll say it is readable while one is pending.
// - signalfd on a signalfd gives it another mask; on anything else it is
//   EINVAL, and so are flags it does not have and a mask of another size.
//   SIGKILL and SIGSTOP are left out of a mask without complaint.
// - A signal from another process ends a read that waits, and a child's
//   end is read as SIGCHLD.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("signalfd: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static int readable(int fd, int ms) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int n = poll(&p, 1, ms);
    if (n < 0) die("poll", 0, 0);
    return n == 1 && (p.revents & POLLIN);
}

int main(void) {
    int rt = SIGRTMIN + 1;
    sigset_t mask, was;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, rt);
    if (sigprocmask(SIG_BLOCK, &mask, &was)) die("sigprocmask", 0, 0);
    // The descriptor's own mask leaves SIGTERM out, and has two signals
    // nobody can hold back.
    sigset_t mine = mask;
    sigdelset(&mine, SIGTERM);
    sigaddset(&mine, SIGKILL);
    sigaddset(&mine, SIGSTOP);
    int fd = signalfd(-1, &mine, SFD_CLOEXEC | SFD_NONBLOCK);
    if (fd < 0) die("signalfd", 0, 0);
    if (!(fcntl(fd, F_GETFD) & FD_CLOEXEC) || !(fcntl(fd, F_GETFL) & O_NONBLOCK)) die("its flags", fcntl(fd, F_GETFD), fcntl(fd, F_GETFL));

    struct signalfd_siginfo si[4];
    if (read(fd, si, sizeof si) != -1 || errno != EAGAIN) die("a read with nothing pending", errno, 0);
    if (read(fd, si, sizeof si[0] - 1) != -1 || errno != EINVAL) die("a read into less than one", errno, 0);
    if (readable(fd, 0)) die("readable with nothing pending", 0, 0);

    // One to this thread, three to the process: the thread's own is read
    // first though its number is higher.
    union sigval value = {.sival_ptr = (void *)0x100001234};
    if (raise(SIGUSR2) || kill(getpid(), SIGUSR1) || sigqueue(getpid(), rt, value) || kill(getpid(), SIGTERM)) die("raise", 0, 0);
    if (!readable(fd, 0)) die("not readable with signals pending", 0, 0);
    ssize_t n = read(fd, si, sizeof si);
    if (n != 3 * (ssize_t)sizeof si[0]) die("a read of three", n, 0);
    if (si[0].ssi_signo != SIGUSR2 || si[0].ssi_code != SI_TKILL || si[0].ssi_pid != (uint32_t)getpid() || si[0].ssi_uid != getuid()) die("the thread's own signal", si[0].ssi_signo, si[0].ssi_code);
    if (si[1].ssi_signo != SIGUSR1 || si[1].ssi_code != SI_USER || si[1].ssi_pid != (uint32_t)getpid() || si[1].ssi_uid != getuid()) die("the process's signal", si[1].ssi_signo, si[1].ssi_code);
    if (si[2].ssi_signo != (uint32_t)rt || si[2].ssi_code != SI_QUEUE || si[2].ssi_pid != (uint32_t)getpid() || si[2].ssi_ptr != 0x100001234 || si[2].ssi_int != 0x1234) die("the queued signal", si[2].ssi_signo, si[2].ssi_int);
    for (size_t i = 0; i < sizeof si[0].__pad; i++) {
        if (si[0].__pad[i]) die("bytes past the fields", i, si[0].__pad[i]);
    }
    if (read(fd, si, sizeof si) != -1 || errno != EAGAIN || readable(fd, 0)) die("a read after all were taken", errno, 0);
    // SIGTERM was not its to take.
    sigset_t pending;
    sigpending(&pending);
    if (!sigismember(&pending, SIGTERM) || sigismember(&pending, SIGUSR1)) die("what is still pending", 0, 0);

    // Another mask for the same descriptor: now SIGTERM alone.
    sigset_t term;
    sigemptyset(&term);
    sigaddset(&term, SIGTERM);
    if (signalfd(fd, &term, 0) != fd) die("a new mask", 0, 0);
    if (!(fcntl(fd, F_GETFL) & O_NONBLOCK)) die("the flags after a new mask", 0, 0);
    kill(getpid(), SIGUSR1);
    if (read(fd, si, sizeof si) != (ssize_t)sizeof si[0] || si[0].ssi_signo != SIGTERM) die("a read under the new mask", si[0].ssi_signo, 0);
    if (readable(fd, 0)) die("readable for a signal out of the mask", 0, 0);
    struct timespec none = {0};
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    if (sigtimedwait(&usr1, NULL, &none) != SIGUSR1) die("the signal left pending", 0, 0);

    // What is refused.
    int pipes[2];
    if (pipe(pipes)) die("pipe", 0, 0);
    if (signalfd(pipes[0], &mine, 0) != -1 || errno != EINVAL) die("signalfd on a pipe", errno, 0);
    if (signalfd(999, &mine, 0) != -1 || errno != EBADF) die("signalfd on no descriptor", errno, 0);
    if (signalfd(-1, &mine, 1) != -1 || errno != EINVAL) die("a flag it does not have", errno, 0);
    uint64_t raw = 1 << (SIGUSR1 - 1);
    if (syscall(SYS_signalfd4, -1, &raw, 4, 0) != -1 || errno != EINVAL) die("a mask of four bytes", errno, 0);
    if (syscall(SYS_signalfd4, -1, (void *)8, 8, 0) != -1 || errno != EFAULT) die("a mask that cannot be read", errno, 0);
    if (write(fd, &raw, sizeof raw) != -1 || errno != EINVAL) die("a write", errno, 0);

    // A read that waits, ended by a child's signal; then the child's end,
    // waited for by epoll.
    int blocking = signalfd(-1, &mine, SFD_CLOEXEC);
    if (blocking < 0) die("signalfd", 0, 0);
    pid_t child = fork();
    if (child == 0) {
        usleep(100 * 1000);
        kill(getppid(), SIGUSR1);
        usleep(100 * 1000);
        _exit(7);
    }
    if (read(blocking, si, sizeof si[0]) != (ssize_t)sizeof si[0]) die("a read that waits", 0, 0);
    if (si[0].ssi_signo != SIGUSR1 || si[0].ssi_code != SI_USER || si[0].ssi_pid != (uint32_t)child) die("the child's signal", si[0].ssi_signo, si[0].ssi_pid);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = blocking};
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, blocking, &ev)) die("epoll", 0, 0);
    if (epoll_wait(ep, &ev, 1, 10000) != 1 || ev.data.fd != blocking) die("epoll_wait for the child's end", 0, 0);
    if (read(blocking, si, sizeof si[0]) != (ssize_t)sizeof si[0]) die("a read after epoll", 0, 0);
    if (si[0].ssi_signo != SIGCHLD || si[0].ssi_code != CLD_EXITED || si[0].ssi_pid != (uint32_t)child || si[0].ssi_status != 7 || si[0].ssi_uid != getuid()) die("the child's end", si[0].ssi_code, si[0].ssi_status);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 7) die("waitpid", status, 0);

    printf("signalfd ok\n");
    return 0;
}
