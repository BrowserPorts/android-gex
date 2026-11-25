// net.ipv4.ip_forward, as TetherController sets it: the same setting as
// net.ipv4.conf.all.forwarding, so a write to either reads back through
// the other, and the write carries to conf/default and every interface's
// conf (lo here). Listed in /proc/sys/net/ipv4. As root; on Linux in a
// network namespace of its own (fresh settings, the host's untouched),
// where there is none (gex) in place, with the old value put back.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("ipforward: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static long get(const char *path) {
    char b[32] = {0};
    int fd = open(path, O_RDONLY);
    long n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return -1;
    long v = -1;
    sscanf(b, "%ld", &v);
    return v;
}

static long set(const char *path, const char *v) {
    int fd = open(path, O_WRONLY);
    long n = fd < 0 ? -1 : write(fd, v, strlen(v));
    if (fd >= 0) close(fd);
    return n;
}

int main(void) {
    // A fresh network namespace where there is one.
    (void)unshare(CLONE_NEWNET);
    const char *fwd = "/proc/sys/net/ipv4/ip_forward";
    const char *all = "/proc/sys/net/ipv4/conf/all/forwarding";
    long was = get(fwd);
    want("ip_forward reads", was >= 0, 1);
    want("it is all/forwarding", get(all), was);

    want("write 1", set(fwd, "1\n"), 2);
    want("ip_forward", get(fwd), 1);
    want("all", get(all), 1);
    want("default", get("/proc/sys/net/ipv4/conf/default/forwarding"), 1);
    want("lo", get("/proc/sys/net/ipv4/conf/lo/forwarding"), 1);

    want("write 0 to all", set(all, "0"), 1);
    want("ip_forward after", get(fwd), 0);
    want("lo after", get("/proc/sys/net/ipv4/conf/lo/forwarding"), 0);

    int listed = 0;
    DIR *d = opendir("/proc/sys/net/ipv4");
    for (struct dirent *e; d && (e = readdir(d));) {
        if (!strcmp(e->d_name, "ip_forward")) listed = 1;
    }
    if (d) closedir(d);
    want("listed", listed, 1);

    char v[8];
    snprintf(v, sizeof v, "%ld", was);
    set(fwd, v);
    if (!failed) printf("ipforward ok\n");
    return failed;
}
