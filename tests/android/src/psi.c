// Pressure-stall information: /proc/pressure/memory, cpu and io say how
// much of the time tasks waited for each, and a program arms a trigger on
// one to be told (POLLPRI) when a stall passes a threshold. Android's
// lmkd arms three on memory before anything else and ends without the
// file; the system server reads them.
//
// - Each file reads a "some" and a "full" line: three averages and a
//   total.
// - With no trigger, poll says POLLPRI and POLLERR at once.
// - A write of "some" or "full", a stall and a window in microseconds
//   arms a trigger on that open file: one a file (EBUSY for a second), a
//   window of no more than ten seconds and not 0, a stall of no more than
//   the window and not 0 (EINVAL), and no other word (EINVAL).
// - An armed trigger whose threshold is the whole window is not reported:
//   a poll for POLLPRI runs out its time.
//
// Needs root: a trigger with a window that is not a multiple of two
// seconds is refused without CAP_SYS_RESOURCE on a kernel whose default
// security module is not SELinux.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("psi: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

// Arm `text` on a new descriptor of the memory file: the descriptor, or
// minus the errno.
static int arm(const char *text) {
    int fd = open("/proc/pressure/memory", O_RDWR | O_NONBLOCK);
    if (fd < 0) die("open", errno, 0);
    if (write(fd, text, strlen(text) + 1) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}

int main(void) {
    if (geteuid() != 0) {
        printf("psi: needs root\n");
        return 77;
    }
    const char *files[] = {"/proc/pressure/memory", "/proc/pressure/cpu", "/proc/pressure/io"};
    for (int i = 0; i < 3; i++) {
        struct stat st;
        if (stat(files[i], &st) || !S_ISREG(st.st_mode) || (st.st_mode & 0777) != 0666) die(files[i], st.st_mode, 0);
        char buf[256] = {0};
        int fd = open(files[i], O_RDONLY);
        if (fd < 0 || read(fd, buf, sizeof buf - 1) <= 0) die("a read", i, errno);
        float a, b, c, d, e, f;
        unsigned long long some, full;
        if (sscanf(buf, "some avg10=%f avg60=%f avg300=%f total=%llu\nfull avg10=%f avg60=%f avg300=%f total=%llu\n", &a, &b, &c, &some, &d, &e, &f, &full) != 8) die("what a pressure file reads", i, 0);
        // No trigger: reported at once.
        struct pollfd p = {fd, POLLPRI, 0};
        if (poll(&p, 1, 0) != 1 || (p.revents & (POLLPRI | POLLERR)) != (POLLPRI | POLLERR)) die("poll with no trigger", p.revents, i);
        close(fd);
    }

    int fd = arm("some 1000000 1000000");
    if (fd < 0) die("arming a trigger", -fd, 0);
    if (write(fd, "some 1000000 1000000", 21) != -1 || errno != EBUSY) die("a second trigger on one file", errno, 0);
    struct pollfd p = {fd, POLLPRI, 0};
    if (poll(&p, 1, 300) != 0) die("a trigger nothing reaches", p.revents, 0);
    close(fd);
    if ((fd = arm("full 500000 10000000")) < 0) die("a full trigger, the longest window", -fd, 0);
    close(fd);
    if ((fd = arm("some 150000 1000000")) < 0) die("a trigger as lmkd arms it", -fd, 0);
    close(fd);

    if (arm("some 0 1000000") != -EINVAL) die("no stall", 0, 0);
    if (arm("some 1000 0") != -EINVAL) die("no window", 0, 0);
    if (arm("some 2000000 1000000") != -EINVAL) die("a stall longer than its window", 0, 0);
    if (arm("some 1000 10000001") != -EINVAL) die("a window over ten seconds", 0, 0);
    if (arm("most 1000 1000000") != -EINVAL) die("another word", 0, 0);
    if (arm("some 1000") != -EINVAL) die("one number", 0, 0);
    if (arm("some") != -EINVAL) die("no number", 0, 0);

    printf("psi ok\n");
    return 0;
}
