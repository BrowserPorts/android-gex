// /proc/<pid>/status's first fields, in Linux's order and form, for the
// process itself and for a child it waits on: libprocinfo (Android's
// crash_dump, debuggerd, init) wants Name, Tgid, Pid, TracerPid, Uid and
// Gid, and fails on a status without any of them. Prints each header in
// order up to Gid, with Umask's value; checks against Linux 7.0's.
#define _GNU_SOURCE
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "self: Name: Umask:0027 State: Tgid: Ngid: Pid: PPid: TracerPid: Uid: Gid:\n"
    "child: Name: Umask:0077 State: Tgid: Ngid: Pid: PPid: TracerPid: Uid: Gid:\n";

static char out_buf[2048];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[256];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static void headers(const char *who, const char *path) {
    FILE *f = fopen(path, "r");
    char line[512];
    SAY("%s:", who);
    while (f && fgets(line, sizeof line, f)) {
        char *tab = strchr(line, '\t');
        if (!tab)
            continue;
        *tab = 0;
        SAY(" %s", line);
        if (!strcmp(line, "Umask:"))
            SAY("%s", strtok(tab + 1, "\n"));
        if (!strcmp(line, "Gid:"))
            break;
    }
    SAY("\n");
    if (f)
        fclose(f);
}

int main(void) {
    umask(027);
    headers("self", "/proc/self/status");
    int ready[2];
    if (pipe(ready) != 0)
        return 2;
    pid_t child = fork();
    if (child == 0) {
        umask(077);
        close(ready[0]);
        write(ready[1], "x", 1);
        pause();
        _exit(0);
    }
    char c;
    read(ready[0], &c, 1);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", child);
    headers("child", path);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("procstatus: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "procstatus ok\n" : "procstatus done\n");
    return 0;
}
