// cgroup v2's core, in a subtree of its own (so the controllers a system
// has enabled above it do not show): what a cgroup holds, making and
// removing them, moving processes by cgroup.procs, /proc/<pid>/cgroup,
// cgroup.events and its populated count, the limits on depth and
// descendants, cgroup.stat, cgroup.type, cgroup.kill, what is refused.
// Prints an answer a line and checks them against Linux 7.0's. As root.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "make the test's own: 0\n"
    "into it: 1\n"
    "where: 0::\n"
    "make a: 0\n"
    "make a again: -17\n"
    "a: cgroup.controllers 444 cgroup.events 444 cgroup.freeze 644 cgroup.kill 200 cgroup.max.depth 644 cgroup.max.descendants 644 cgroup.pressure 644 cgroup.procs 644 cgroup.stat 444 cgroup.stat.local 444 cgroup.subtree_control 644 cgroup.threads 644 cgroup.type 644 cpu.pressure 644 cpu.stat 444 cpu.stat.local 444 io.pressure 644 memory.pressure 644\n"
    "a's controllers: [] subtree: [] type: domain|\n"
    "a's events: populated 0|frozen 0|\n"
    "a's limits: max| max|\n"
    "a's stat: nr_descendants 0|nr_dying_descendants 0|\n"
    "a's local stat: frozen_usec \n"
    "a's cpu stat: usage_usec user_usec system_usec nice_usec \n"
    "a's local cpu stat: []\n"
    "a's freeze: 0|\n"
    "a's procs: [] threads: []\n"
    "a file made in a: -13\n"
    "a's pressure: 1|\n"
    "the child into a: 1\n"
    "where it is: 0::/a\n"
    "and I: 0::\n"
    "a's procs is it: 1\n"
    "a's events: populated 1|frozen 0|\n"
    "the root's stat: nr_descendants 1|nr_dying_descendants 0|\n"
    "a pid that is not: -3\n"
    "not a number: -22\n"
    "remove a while it holds one: -16\n"
    "make a/b: 0, a/b/c: 0\n"
    "the root's stat: nr_descendants 3|nr_dying_descendants 0|\n"
    "a's stat: nr_descendants 2|nr_dying_descendants 0|\n"
    "the child into a/b: 1\n"
    "where it is: 0::/a/b\n"
    "a's events: populated 1|frozen 0|\n"
    "a/b's events: populated 1|frozen 0|\n"
    "a's depth 1: 1\n"
    "make a/b/c/d over it: -11\n"
    "a's depth back: 3, descendants 2: 1\n"
    "make a/b/e over it: -11\n"
    "a's limits: max| 2|\n"
    "a's depth -1: -34, abc: -22\n"
    "a controller not there: -22, nonsense: -22\n"
    "type nonsense: -22, domain again: -22\n"
    "a/b/c's type: domain|\n"
    "kill 2: -34\n"
    "kill on a: 1\n"
    "the child: signalled 9\n"
    "a/b's events told: 1 0xa, now populated 0|frozen 0|\n"
    "the root's kill: -2\n"
    "remove a with children: -16\n"
    "remove a/b/c, a/b, a: 0 0 0\n"
    "away: 0\n"
;

static char out_buf[16384];
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

static char root[256];

static const char *at(const char *rel) {
    static char p[4][512];
    static int k;
    k = (k + 1) % 4;
    snprintf(p[k], sizeof p[k], "%s/%s", root, rel);
    return p[k];
}

// A file's contents, newlines shown as '|'.
static const char *get(const char *rel) {
    static char b[4][1024];
    static int k;
    k = (k + 1) % 4;
    int fd = open(at(rel), O_RDONLY);
    if (fd < 0) {
        snprintf(b[k], sizeof b[k], "(%s)", strerror(errno));
        return b[k];
    }
    ssize_t n = read(fd, b[k], sizeof b[k] - 1);
    close(fd);
    if (n < 0) {
        snprintf(b[k], sizeof b[k], "(read %s)", strerror(errno));
        return b[k];
    }
    b[k][n] = 0;
    for (char *c = b[k]; *c; c++)
        if (*c == '\n') *c = '|';
    return b[k];
}

static long put(const char *rel, const char *v) {
    int fd = open(at(rel), O_WRONLY);
    if (fd < 0) return -errno;
    long r = write(fd, v, strlen(v));
    long e = r < 0 ? -errno : r;
    close(fd);
    return e;
}

// A file's lines that do not name a controller (which ones a kernel has
// bound to the hierarchy is its own).
static const char *core(const char *rel) {
    static char b[1024];
    const char *all = get(rel);
    b[0] = 0;
    const char *l = all;
    while (*l) {
        const char *e = strchr(l, '|');
        size_t n = e ? (size_t)(e - l + 1) : strlen(l);
        if (strncmp(l, "nr_subsys_", 10) != 0 && strncmp(l, "nr_dying_subsys_", 16) != 0) strncat(b, l, n);
        l += n;
    }
    return b;
}

// A file's field names, one a line.
static const char *names(const char *rel) {
    static char b[1024];
    const char *all = get(rel);
    b[0] = 0;
    const char *l = all;
    while (*l) {
        const char *sp = strchr(l, ' ');
        const char *e = strchr(l, '|');
        if (!sp || !e) break;
        // (Not core scheduling's, which GKI is built without.)
        if (strncmp(l, "core_sched.", 11) != 0) {
            strncat(b, l, (size_t)(sp - l));
            strcat(b, " ");
        }
        l = e + 1;
    }
    return b;
}

static int cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void list(const char *rel) {
    DIR *d = opendir(at(rel));
    char *names[128];
    int n = 0;
    struct dirent *e;
    // (Not irq.pressure, which a kernel has with IRQ_TIME_ACCOUNTING:
    // GKI's has it, the oracle's has not.)
    while (d && (e = readdir(d)) && n < 128)
        if (e->d_name[0] != '.' && strcmp(e->d_name, "irq.pressure") != 0) names[n++] = strdup(e->d_name);
    if (d) closedir(d);
    qsort(names, n, sizeof *names, cmp);
    SAY("%s:", rel);
    for (int i = 0; i < n; i++) {
        struct stat st;
        char p[600];
        snprintf(p, sizeof p, "%s/%s", rel, names[i]);
        stat(at(p), &st);
        SAY(" %s %o", names[i], st.st_mode & 07777);
        free(names[i]);
    }
    SAY("\n");
}

// Where /proc/<pid>/cgroup says a process is, from the test's root.
static const char *where(pid_t pid) {
    static char b[512];
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/cgroup", pid);
    FILE *f = fopen(p, "r");
    if (!f) return "(none)";
    char line[512] = "";
    if (!fgets(line, sizeof line, f)) line[0] = 0;
    fclose(f);
    line[strcspn(line, "\n")] = 0;
    // "0::/<root>/x": the part under the test's root.
    const char *mine = strstr(line, "/gextest");
    snprintf(b, sizeof b, "%.3s%s", line, mine ? mine + strlen("/gextest") : line + 3);
    return b;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    // The hierarchy, mounted here (on Linux the same one the system has;
    // under gex, not the host's own /sys).
    const char *base = "/tmp/gexcg";
    mkdir(base, 0755);
    if (mount("none", base, "cgroup2", 0, NULL) != 0) {
        printf("cgroup2: no mount: %s\n", strerror(errno));
        return 1;
    }
    snprintf(root, sizeof root, "%s/gextest", base);
    rmdir(at("a/b/c"));
    rmdir(at("a/b"));
    rmdir(at("a"));
    rmdir(root);
    SAY("make the test's own: %d\n", mkdir(root, 0755) == 0 ? 0 : -errno);
    // Moved into it, so what is under it is what it makes.
    SAY("into it: %ld\n", put("cgroup.procs", "0"));
    SAY("where: %s\n", where(getpid()));
    SAY("make a: %d\n", mkdir(at("a"), 0755) == 0 ? 0 : -errno);
    SAY("make a again: %d\n", mkdir(at("a"), 0755) == 0 ? 0 : -errno);
    list("a");
    SAY("a's controllers: [%s] subtree: [%s] type: %s\n", get("a/cgroup.controllers"), get("a/cgroup.subtree_control"), get("a/cgroup.type"));
    SAY("a's events: %s\n", get("a/cgroup.events"));
    SAY("a's limits: %s %s\n", get("a/cgroup.max.depth"), get("a/cgroup.max.descendants"));
    SAY("a's stat: %s\n", core("a/cgroup.stat"));
    SAY("a's local stat: %s\n", names("a/cgroup.stat.local"));
    SAY("a's cpu stat: %s\n", names("a/cpu.stat"));
    SAY("a's local cpu stat: [%s]\n", get("a/cpu.stat.local"));
    SAY("a's freeze: %s\n", get("a/cgroup.freeze"));
    SAY("a's procs: [%s] threads: [%s]\n", get("a/cgroup.procs"), get("a/cgroup.threads"));
    SAY("a file made in a: %d\n", open(at("a/x"), O_CREAT | O_WRONLY, 0644) >= 0 ? 0 : -errno);
    SAY("a's pressure: %s\n", get("a/cgroup.pressure"));

    // A child process into a.
    int go[2];
    if (pipe(go) != 0) return 1;
    pid_t c = fork();
    if (c == 0) {
        char x;
        read(go[0], &x, 1);
        _exit(0);
    }
    char pid[32];
    snprintf(pid, sizeof pid, "%d", c);
    // (Whether the write was taken whole: pids are of other lengths.)
    SAY("the child into a: %d\n", put("a/cgroup.procs", pid) == (long)strlen(pid));
    SAY("where it is: %s\n", where(c));
    SAY("and I: %s\n", where(getpid()));
    SAY("a's procs is it: %d\n", atoi(get("a/cgroup.procs")) == c);
    SAY("a's events: %s\n", get("a/cgroup.events"));
    SAY("the root's stat: %s\n", core("cgroup.stat"));
    SAY("a pid that is not: %ld\n", put("a/cgroup.procs", "999999"));
    SAY("not a number: %ld\n", put("a/cgroup.procs", "x"));
    SAY("remove a while it holds one: %d\n", rmdir(at("a")) == 0 ? 0 : -errno);
    SAY("make a/b: %d, a/b/c: %d\n", mkdir(at("a/b"), 0755) == 0 ? 0 : -errno, mkdir(at("a/b/c"), 0755) == 0 ? 0 : -errno);
    SAY("the root's stat: %s\n", core("cgroup.stat"));
    SAY("a's stat: %s\n", core("a/cgroup.stat"));
    // A process in a cgroup with children of its own: no (the "no internal
    // processes" rule holds only with controllers enabled for them).
    SAY("the child into a/b: %d\n", put("a/b/cgroup.procs", pid) == (long)strlen(pid));
    SAY("where it is: %s\n", where(c));
    SAY("a's events: %s\n", get("a/cgroup.events"));
    SAY("a/b's events: %s\n", get("a/b/cgroup.events"));
    // Limits.
    SAY("a's depth 1: %ld\n", put("a/cgroup.max.depth", "1"));
    SAY("make a/b/c/d over it: %d\n", mkdir(at("a/b/c/d"), 0755) == 0 ? 0 : -errno);
    SAY("a's depth back: %ld, descendants 2: %ld\n", put("a/cgroup.max.depth", "max"), put("a/cgroup.max.descendants", "2"));
    SAY("make a/b/e over it: %d\n", mkdir(at("a/b/e"), 0755) == 0 ? 0 : -errno);
    SAY("a's limits: %s %s\n", get("a/cgroup.max.depth"), get("a/cgroup.max.descendants"));
    SAY("a's depth -1: %ld, abc: %ld\n", put("a/cgroup.max.depth", "-1"), put("a/cgroup.max.depth", "abc"));
    SAY("a controller not there: %ld, nonsense: %ld\n", put("a/cgroup.subtree_control", "+nosuch"), put("a/cgroup.subtree_control", "nosuch"));
    // (Not asked: a threaded cgroup, which Android does not make.)
    SAY("type nonsense: %ld, domain again: %ld\n", put("a/b/c/cgroup.type", "x"), put("a/b/c/cgroup.type", "domain"));
    SAY("a/b/c's type: %s\n", get("a/b/c/cgroup.type"));
    // Kill: the child, by its cgroup.
    struct pollfd pf = {open(at("a/b/cgroup.events"), O_RDONLY), POLLPRI, 0};
    char ev[128];
    read(pf.fd, ev, sizeof ev);
    SAY("kill 2: %ld\n", put("a/b/cgroup.kill", "2"));
    SAY("kill on a: %ld\n", put("a/cgroup.kill", "1"));
    int st2 = 0;
    waitpid(c, &st2, 0);
    SAY("the child: %s %d\n", WIFSIGNALED(st2) ? "signalled" : "exited", WIFSIGNALED(st2) ? WTERMSIG(st2) : WEXITSTATUS(st2));
    int pr = poll(&pf, 1, 1000);
    SAY("a/b's events told: %d %#x, now %s\n", pr, pf.revents, get("a/b/cgroup.events"));
    close(pf.fd);
    SAY("the root's kill: %ld\n", put("../cgroup.kill", "1"));
    SAY("remove a with children: %d\n", rmdir(at("a")) == 0 ? 0 : -errno);
    SAY("remove a/b/c, a/b, a: %d %d %d\n", rmdir(at("a/b/c")) == 0 ? 0 : -errno, rmdir(at("a/b")) == 0 ? 0 : -errno,
        rmdir(at("a")) == 0 ? 0 : -errno);
    // Back out, and the test's own away.
    char me[32];
    snprintf(me, sizeof me, "%d", getpid());
    put("../cgroup.procs", me);
    SAY("away: %d\n", rmdir(root) == 0 ? 0 : -errno);
    umount(base);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("cgroup2: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "cgroup2 ok\n" : "cgroup2 done\n");
    return 0;
}
