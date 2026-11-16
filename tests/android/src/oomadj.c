// /proc/<pid>/oom_score_adj: how readily the kernel ends a process when
// memory runs out, from -1000 (never) to 1000. Android's init writes
// -1000 to its own before anything else, lmkd and the activity manager
// write every app's as it comes and goes, and they read it back.
//
// - It reads as a number and a newline, by /proc/self and by the
//   process's own number, and is what was last written.
// - A write is a number as the kernel reads one whole: space around it
//   dropped, a sign, 0x for sixteen. -1000 to 1000; outside that, letters
//   and nothing at all are EINVAL and change nothing.
// - A fork's child begins with its parent's, and its own writes are its
//   own.
// - Lowering it below the least it was set to by a process with
//   CAP_SYS_RESOURCE takes that capability (EACCES without); raising it
//   does not.
//
// Needs root for the last; what the value was is put back.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("oomadj: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static long get(const char *path) {
    char buf[32] = {0};
    int fd = open(path, O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
    if (n < 2 || buf[n - 1] != '\n') die(path, n, errno);
    close(fd);
    return strtol(buf, NULL, 10);
}

// Write `text` through `fd`: 0, or the errno.
static int put(int fd, const char *text) {
    ssize_t n = write(fd, text, strlen(text));
    if (n >= 0 && (size_t)n != strlen(text)) die("a short write", n, 0);
    return n < 0 ? errno : 0;
}

#define SELF "/proc/self/oom_score_adj"

int main(void) {
    if (geteuid() != 0) {
        printf("oomadj: needs root\n");
        return 77;
    }
    struct stat st;
    if (stat(SELF, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 0777) != 0644) die("the file", st.st_mode, 0);
    long was = get(SELF);
    int fd = open(SELF, O_WRONLY);
    if (fd < 0) die("open to write", errno, 0);

    if (put(fd, "500") || get(SELF) != 500) die("a number", get(SELF), 0);
    char by_pid[64];
    snprintf(by_pid, sizeof by_pid, "/proc/%d/oom_score_adj", getpid());
    if (get(by_pid) != 500) die("by the process's number", get(by_pid), 0);
    if (put(fd, "-1000\n") || get(SELF) != -1000) die("the least", get(SELF), 0);
    if (put(fd, "1000\n") || get(SELF) != 1000) die("the most", get(SELF), 0);
    if (put(fd, "1001\n") != EINVAL || put(fd, "-1001\n") != EINVAL || get(SELF) != 1000) die("out of range", get(SELF), 0);
    if (put(fd, "abc\n") != EINVAL || put(fd, "\n") != EINVAL || put(fd, "12x\n") != EINVAL || put(fd, "1 2\n") != EINVAL || get(SELF) != 1000) die("what is not a number", get(SELF), 0);
    if (put(fd, "  300 \n") || get(SELF) != 300) die("space around it", get(SELF), 0);
    if (put(fd, "0x10\n") || get(SELF) != 16) die("0x is base sixteen", get(SELF), 0);
    if (put(fd, "+7\n") || get(SELF) != 7) die("a plus sign", get(SELF), 0);

    // A child begins with it, and has its own.
    if (put(fd, "200\n")) die("200", errno, 0);
    pid_t child = fork();
    if (child < 0) die("fork", errno, 0);
    if (child == 0) {
        if (get(SELF) != 200) die("a child's, at first", get(SELF), 0);
        int mine = open(SELF, O_WRONLY);
        if (mine < 0 || put(mine, "400\n") || get(SELF) != 400) die("a child's own", get(SELF), errno);
        // Without the capability: up, and down as far as it was last
        // put with the capability (the 400 just written), and no further.
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) die("becoming a user", errno, 0);
        if (put(mine, "600\n")) die("raising it without the capability", errno, 0);
        if (put(mine, "450\n")) die("lowering it to above the least", errno, 0);
        if (put(mine, "400\n")) die("lowering it to the least", errno, 0);
        if (put(mine, "399\n") != EACCES || get(SELF) != 400) die("lowering it below the least", errno, get(SELF));
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    if (get(SELF) != 200) die("the parent's, after its child's writes", get(SELF), 0);

    char text[32];
    snprintf(text, sizeof text, "%ld\n", was);
    if (put(fd, text) || get(SELF) != was) die("putting it back", get(SELF), was);
    printf("oomadj ok\n");
    return 0;
}
