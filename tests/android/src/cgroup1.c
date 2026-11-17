// cgroup v1's core, in a named hierarchy of its own (the oracle's
// controllers are all bound to version 2, so none can be mounted at
// version 1 there): its files and their modes, a group made, a process
// moved by tasks and cgroup.procs, /proc/self/cgroup's line for it, the
// flags each group has, what is refused, mounting it again. Prints an
// answer a line and checks them against Linux 7.0's. As root.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "none alone: -22\n"
    "named: 0\n"
    "the root: cgroup.clone_children 644 cgroup.procs 644 cgroup.sane_behavior 444 notify_on_release 644 release_agent 644 tasks 644\n"
    "release_agent [|]\n"
    "notify_on_release 0|\n"
    "clone_children 0|\n"
    "sane_behavior 0|\n"
    "where I am: name=gexv1t:/\n"
    "make a: 0\n"
    "a: cgroup.clone_children 644 cgroup.procs 644 notify_on_release 644 tasks 644\n"
    "into a by tasks: 0\n"
    "where I am: name=gexv1t:/a\n"
    "a's procs and tasks are me: 1 1\n"
    "a task not there: -3, not a number: -22\n"
    "notify_on_release 1: 0, 2: 0, -1: -22, x: -22\n"
    "now 1|\n"
    "clone_children 0: 0, now 0|\n"
    "remove a while I am in it: -16\n"
    "back by cgroup.procs: 0, where I am: name=gexv1t:/\n"
    "mounted again: 0, a there: 1\n"
    "a file made in a: -13\n"
    "remove a: 0\n"
;

static char out_buf[8192];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[1024];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static const char *base = "/tmp/gexv1";

static const char *get(const char *rel) {
    static char b[2][512];
    static int k;
    k ^= 1;
    char p[256];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    int fd = open(p, O_RDONLY);
    if (fd < 0) {
        snprintf(b[k], sizeof b[k], "(%s)", strerror(errno));
        return b[k];
    }
    ssize_t n = read(fd, b[k], sizeof b[k] - 1);
    close(fd);
    b[k][n < 0 ? 0 : n] = 0;
    for (char *c = b[k]; *c; c++)
        if (*c == '\n') *c = '|';
    return b[k];
}

static long put(const char *rel, const char *v) {
    char p[256];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    int fd = open(p, O_WRONLY);
    if (fd < 0) return -errno;
    long r = write(fd, v, strlen(v));
    long e = r < 0 ? -errno : 0;
    close(fd);
    return e;
}

static int cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void list(const char *rel) {
    char p[256];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    DIR *d = opendir(p);
    char *names[64];
    int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) && n < 64)
        if (e->d_name[0] != '.') names[n++] = strdup(e->d_name);
    if (d) closedir(d);
    qsort(names, n, sizeof *names, cmp);
    SAY("%s:", rel[0] ? rel : "the root");
    for (int i = 0; i < n; i++) {
        struct stat st;
        char q[512];
        snprintf(q, sizeof q, "%s/%s", p, names[i]);
        stat(q, &st);
        SAY(" %s %o", names[i], st.st_mode & 07777);
        free(names[i]);
    }
    SAY("\n");
}

// This hierarchy's line of /proc/self/cgroup, without its number.
static const char *mine(void) {
    static char line[256];
    FILE *f = fopen("/proc/self/cgroup", "r");
    line[0] = 0;
    char l[256];
    while (f && fgets(l, sizeof l, f))
        if (strstr(l, "name=gexv1t")) {
            l[strcspn(l, "\n")] = 0;
            snprintf(line, sizeof line, "%s", strchr(l, ':') + 1);
        }
    if (f) fclose(f);
    return line;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mkdir(base, 0755);
    SAY("none alone: %d\n", mount("none", base, "cgroup", 0, "none") == 0 ? 0 : -errno);
    SAY("named: %d\n", mount("none", base, "cgroup", 0, "none,name=gexv1t") == 0 ? 0 : -errno);
    list("");
    SAY("release_agent [%s]\n", get("release_agent"));
    SAY("notify_on_release %s\n", get("notify_on_release"));
    SAY("clone_children %s\n", get("cgroup.clone_children"));
    SAY("sane_behavior %s\n", get("cgroup.sane_behavior"));
    SAY("where I am: %s\n", mine());
    SAY("make a: %d\n", mkdir("/tmp/gexv1/a", 0755) == 0 ? 0 : -errno);
    list("a");
    char me[32];
    snprintf(me, sizeof me, "%d", getpid());
    SAY("into a by tasks: %ld\n", put("a/tasks", me));
    SAY("where I am: %s\n", mine());
    SAY("a's procs and tasks are me: %d %d\n", atoi(get("a/cgroup.procs")) == getpid(), atoi(get("a/tasks")) == getpid());
    SAY("a task not there: %ld, not a number: %ld\n", put("a/tasks", "999999"), put("a/tasks", "x"));
    SAY("notify_on_release 1: %ld, 2: %ld, -1: %ld, x: %ld\n", put("a/notify_on_release", "1"), put("a/notify_on_release", "2"),
        put("a/notify_on_release", "-1"), put("a/notify_on_release", "x"));
    SAY("now %s\n", get("a/notify_on_release"));
    SAY("clone_children 0: %ld, now %s\n", put("a/cgroup.clone_children", "0"), get("a/cgroup.clone_children"));
    SAY("remove a while I am in it: %d\n", rmdir("/tmp/gexv1/a") == 0 ? 0 : -errno);
    SAY("back by cgroup.procs: %ld, where I am: %s\n", put("cgroup.procs", me), mine());
    // The same hierarchy, mounted again: a is there.
    mkdir("/tmp/gexv1b", 0755);
    SAY("mounted again: %d, a there: %d\n", mount("none", "/tmp/gexv1b", "cgroup", 0, "none,name=gexv1t") == 0 ? 0 : -errno,
        access("/tmp/gexv1b/a", F_OK) == 0);
    umount("/tmp/gexv1b");
    SAY("a file made in a: %d\n", open("/tmp/gexv1/a/x", O_CREAT | O_WRONLY, 0644) >= 0 ? 0 : -errno);
    SAY("remove a: %d\n", rmdir("/tmp/gexv1/a") == 0 ? 0 : -errno);
    umount(base);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("cgroup1: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "cgroup1 ok\n" : "cgroup1 done\n");
    return 0;
}
