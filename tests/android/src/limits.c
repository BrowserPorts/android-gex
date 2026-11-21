// /proc/self/limits and another process's /proc/<pid>/limits, as Linux's
// proc_pid_limits writes them: a header, then a line a resource with its
// soft and hard limits ("unlimited" for infinity) and unit, in columns 25,
// 20, 20 and 10 wide; the nice and realtime priorities have no unit. The
// limits this sets are checked as the lines they must read; the others
// only for their place and name, since a system's defaults differ.
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what, const char *got) {
    printf("limits: %s: got '%s' (errno %d)\n", what, got, errno);
    exit(1);
}

static int read_file(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t got = fread(buf, 1, n - 1, f);
    buf[got] = 0;
    fclose(f);
    return (int)got;
}

// The line of `text` whose name is `name`, without its newline.
static void line_of(const char *text, const char *name, char *out, size_t n) {
    const char *p = text;
    out[0] = 0;
    while (p && *p) {
        const char *end = strchr(p, '\n');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (!strncmp(p, name, strlen(name)) && p[strlen(name)] == ' ') {
            if (len >= n) len = n - 1;
            memcpy(out, p, len);
            out[len] = 0;
            return;
        }
        p = end ? end + 1 : 0;
    }
}

static void want_line(const char *text, const char *name, const char *soft, const char *hard, const char *unit) {
    char got[256], want[256];
    line_of(text, name, got, sizeof got);
    if (*unit)
        snprintf(want, sizeof want, "%-25s %-20s %-20s %-10s", name, soft, hard, unit);
    else
        snprintf(want, sizeof want, "%-25s %-20s %-20s ", name, soft, hard);
    if (strcmp(got, want)) {
        printf("limits: want '%s'\n", want);
        die(name, got);
    }
}

int main(void) {
    // Lowered, not raised, so that no privilege is needed: soft 1000 under
    // the hard limit there is (4096 unless raised), and 900 in the child.
    struct rlimit r;
    getrlimit(RLIMIT_NOFILE, &r);
    char hard[32];
    if (r.rlim_max == RLIM_INFINITY) snprintf(hard, sizeof hard, "unlimited");
    else snprintf(hard, sizeof hard, "%llu", (unsigned long long)r.rlim_max);
    r.rlim_cur = 1000;
    if (setrlimit(RLIMIT_NOFILE, &r)) die("setrlimit nofile", "");
    r.rlim_cur = 0;
    r.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &r)) die("setrlimit core", "");
    r.rlim_cur = RLIM_INFINITY;
    r.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CPU, &r);

    char text[4096], first[256], header[256];
    if (read_file("/proc/self/limits", text, sizeof text) <= 0) die("reading /proc/self/limits", "");
    snprintf(header, sizeof header, "%-25s %-20s %-20s %-10s", "Limit", "Soft Limit", "Hard Limit", "Units");
    sscanf(text, "%255[^\n]", first);
    if (strcmp(first, header)) die("the header", first);
    want_line(text, "Max open files", "1000", hard, "files");
    want_line(text, "Max core file size", "0", "unlimited", "bytes");
    want_line(text, "Max cpu time", "unlimited", "unlimited", "seconds");
    static const char *names[] = {"Max cpu time", "Max file size", "Max data size", "Max stack size", "Max core file size", "Max resident set", "Max processes", "Max open files", "Max locked memory", "Max address space", "Max file locks", "Max pending signals", "Max msgqueue size", "Max nice priority", "Max realtime priority", "Max realtime timeout"};
    int lines = 0;
    for (const char *p = text; *p; p++) lines += *p == '\n';
    if (lines != 17) die("the number of lines", "");
    for (int i = 0; i < 16; i++) {
        char got[256];
        line_of(text, names[i], got, sizeof got);
        if (!got[0]) die("a resource's line", names[i]);
    }
    // The priorities have no unit: the line ends after the hard limit.
    char nice[256];
    line_of(text, "Max nice priority", nice, sizeof nice);
    if (strlen(nice) != 25 + 1 + 20 + 1 + 20 + 1) die("the nice priority's line, which has no unit", nice);

    // Another process's: a child that raises its own and waits.
    int p[2];
    if (pipe(p)) die("pipe", "");
    pid_t child = fork();
    if (child == 0) {
        struct rlimit c;
        getrlimit(RLIMIT_NOFILE, &c);
        c.rlim_cur = 900;
        setrlimit(RLIMIT_NOFILE, &c);
        if (write(p[1], "x", 1) != 1) _exit(1);
        pause();
        _exit(0);
    }
    char c;
    if (read(p[0], &c, 1) != 1) die("the child", "");
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/limits", child);
    if (read_file(path, text, sizeof text) <= 0) die("reading the child's limits", path);
    want_line(text, "Max open files", "900", hard, "files");
    want_line(text, "Max core file size", "0", "unlimited", "bytes");
    kill(child, SIGKILL);
    waitpid(child, 0, 0);
    printf("limits ok\n");
    return 0;
}
