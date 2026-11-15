// RLIMIT_NOFILE as Android's init sets it (`setrlimit nofile 32768
// 524288` in init.rc), and who may.
//
// - A process starts with 1024 and 4096 (unless whoever started it said
//   otherwise: the test sets them itself first).
// - Root (CAP_SYS_RESOURCE) raises the hard limit, up to fs.nr_open and
//   no further (EPERM); a soft limit above the hard one is EINVAL.
// - The soft limit is where descriptors end: one below it can be had,
//   one at it is EBADF from dup2 and EINVAL from F_DUPFD.
// - Without the capability the hard limit only goes down (EPERM up), and
//   the soft limit moves beneath it.
// - A child has its parent's limits.
//
// Needs root; otherwise the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("rlimit: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static int set(rlim_t soft, rlim_t hard) {
    struct rlimit r = {soft, hard};
    return setrlimit(RLIMIT_NOFILE, &r) ? errno : 0;
}

static void expect(rlim_t soft, rlim_t hard, const char *when) {
    struct rlimit r;
    if (getrlimit(RLIMIT_NOFILE, &r) || r.rlim_cur != soft || r.rlim_max != hard) die(when, r.rlim_cur, r.rlim_max);
}

int main(void) {
    if (geteuid() != 0) {
        printf("rlimit: needs root\n");
        return 77;
    }
    char text[32] = {0};
    int fd = open("/proc/sys/fs/nr_open", O_RDONLY);
    if (fd < 0 || read(fd, text, sizeof text - 1) <= 0) die("/proc/sys/fs/nr_open", fd, 0);
    close(fd);
    rlim_t nr_open = strtoul(text, NULL, 10);
    if (nr_open != 1048576) die("fs.nr_open", nr_open, 0);

    if (set(1024, 4096)) die("the limits a process starts with", errno, 0);
    expect(1024, 4096, "the limits a process starts with");
    if (dup2(0, 1023) != 1023) die("a descriptor under the limit", errno, 0);
    if (dup2(0, 1024) >= 0 || errno != EBADF) die("a descriptor at the limit", errno, 0);
    if (fcntl(0, F_DUPFD, 1024) >= 0 || errno != EINVAL) die("F_DUPFD at the limit", errno, 0);

    // As init.rc has it.
    if (set(32768, 524288)) die("setrlimit nofile 32768 524288", errno, 0);
    expect(32768, 524288, "init's limits");
    if (dup2(0, 32767) != 32767) die("a descriptor under the new limit", errno, 0);
    if (dup2(0, 32768) >= 0 || errno != EBADF) die("a descriptor at the new limit", errno, 0);
    if (fcntl(0, F_DUPFD, 5000) != 5000) die("F_DUPFD from 5000", errno, 0);
    close(5000);
    close(32767);

    // To fs.nr_open and no further.
    if (set(32768, nr_open)) die("the hard limit at fs.nr_open", errno, 0);
    if (set(32768, nr_open + 1) != EPERM) die("the hard limit past fs.nr_open", errno, 0);
    if (set(nr_open + 1, nr_open) != EINVAL) die("a soft limit above the hard one", errno, 0);
    if (set(RLIM_INFINITY, RLIM_INFINITY) != EPERM) die("no limit at all", errno, 0);
    expect(32768, nr_open, "the limits after what was refused");
    if (set(32768, 524288)) die("lowering the hard limit", errno, 0);

    // A child has them, and without the capability may only lower.
    pid_t child = fork();
    if (child < 0) die("fork", 0, 0);
    if (child == 0) {
        expect(32768, 524288, "a child's limits");
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) die("dropping root", 0, 0);
        if (set(32768, 524289) != EPERM) die("an ordinary process raising the hard limit", errno, 0);
        if (set(65536, 524288)) die("an ordinary process raising the soft limit", errno, 0);
        if (set(4096, 8192)) die("an ordinary process lowering both", errno, 0);
        if (set(4096, 8193) != EPERM) die("an ordinary process raising it back", errno, 0);
        expect(4096, 8192, "an ordinary process's limits");
        if (dup2(0, 4096) >= 0 || errno != EBADF) die("a descriptor at its limit", errno, 0);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) die("the child", status, 0);
    expect(32768, 524288, "the parent's limits after the child changed its own");

    printf("rlimit ok\n");
    return 0;
}
