// cgroup v2's freezer, as Android freezes cached apps (libprocessgroup
// writes 1 to an app's cgroup.freeze and waits for cgroup.events to say
// frozen): a child in a group of its own writes to a pipe every 10 ms;
// frozen, it writes no more and the group's cgroup.events says frozen 1
// (and the parent group's says frozen 0: it is not frozen itself);
// cgroup.freeze reads 1; thawed, it writes again and frozen is 0; frozen
// again, SIGKILL still ends it. 2 is ERANGE. As root; mounts a cgroup2
// of its own view of the hierarchy at a directory of its own.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("freezer: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static char *slurp(const char *path) {
    static char b[4096];
    int fd = open(path, O_RDONLY);
    long n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
    b[n > 0 ? n : 0] = 0;
    if (fd >= 0) close(fd);
    return b;
}

static long put(const char *path, const char *s) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -errno;
    long r = write(fd, s, strlen(s));
    r = r < 0 ? -errno : r;
    close(fd);
    return r;
}

static void ms(int n) {
    struct timespec t = {n / 1000, (n % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

// What the child wrote in the last `wait_ms`: bytes read.
static long drain(int fd, int wait_ms) {
    ms(wait_ms);
    char b[4096];
    long total = 0, n;
    while ((n = read(fd, b, sizeof b)) > 0) total += n;
    return total;
}

// Wait up to two seconds for cgroup.events to say `frozen <v>`.
static int frozen_is(const char *events, int v) {
    char want_line[16];
    snprintf(want_line, sizeof want_line, "frozen %d\n", v);
    for (int i = 0; i < 200; i++) {
        if (strstr(slurp(events), want_line)) return 1;
        ms(10);
    }
    return 0;
}

int main(void) {
    char root[] = "/tmp/freezer-XXXXXX";
    if (!mkdtemp(root) || mount("none", root, "cgroup2", 0, NULL)) {
        printf("freezer: mount cgroup2: %d\n", errno);
        return 1;
    }
    char parent[256], group[256], f[300];
    snprintf(parent, sizeof parent, "%s/gex-freezer-%d", root, getpid());
    snprintf(group, sizeof group, "%s/child", parent);
    want("mkdir", mkdir(parent, 0755), 0);
    want("mkdir", mkdir(group, 0755), 0);
    int p[2];
    want("pipe", pipe2(p, O_NONBLOCK), 0);
    pid_t c = fork();
    if (c == 0) {
        close(p[0]);
        for (;;) {
            if (write(p[1], "x", 1) < 0 && errno != EAGAIN) _exit(1);
            ms(10);
        }
    }
    close(p[1]);
    char pid[32];
    snprintf(pid, sizeof pid, "%d", c);
    snprintf(f, sizeof f, "%s/cgroup.procs", group);
    want("move the child", put(f, pid), (long)strlen(pid));
    want("it writes", drain(p[0], 200) > 0, 1);

    char freeze[300], events[300], pevents[300];
    snprintf(freeze, sizeof freeze, "%s/cgroup.freeze", group);
    snprintf(events, sizeof events, "%s/cgroup.events", group);
    snprintf(pevents, sizeof pevents, "%s/cgroup.events", parent);
    want("cgroup.freeze reads 0", !strcmp(slurp(freeze), "0\n"), 1);
    want("2", put(freeze, "2"), -ERANGE);
    want("freeze", put(freeze, "1"), 1);
    want("frozen 1", frozen_is(events, 1), 1);
    want("the parent is not frozen", strstr(slurp(pevents), "frozen 0\n") != NULL, 1);
    want("cgroup.freeze reads 1", !strcmp(slurp(freeze), "1\n"), 1);
    drain(p[0], 50);
    want("frozen, it writes nothing", drain(p[0], 300), 0);
    want("thaw", put(freeze, "0"), 1);
    want("frozen 0", frozen_is(events, 0), 1);
    want("thawed, it writes", drain(p[0], 300) > 0, 1);

    want("freeze again", put(freeze, "1"), 1);
    want("frozen 1 again", frozen_is(events, 1), 1);
    want("SIGKILL", kill(c, SIGKILL), 0);
    int st = 0;
    want("it ends", waitpid(c, &st, 0), c);
    want("by SIGKILL", WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, 1);
    want("thaw the empty group", put(freeze, "0"), 1);
    rmdir(group);
    rmdir(parent);
    umount(root);
    rmdir(root);
    if (!failed) printf("freezer ok\n");
    return failed;
}
