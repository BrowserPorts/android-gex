// tracefs as Android uses it: a mount with gid= (every file that group's,
// the root 0700 until chmod), the files' modes, nothing made or removed
// but instances, and, in an instance of its own (so as not to disturb the
// host's tracing): tracing_on, the buffer's size, percent, clock and
// tracer with their refusals, trace_marker as libcutils writes it (the
// count taken, one newline added, the 4054-byte cap, EBADF with tracing
// off, EINVAL with markers off, a stream), trace_marker_raw's limits,
// trace's header and lines and O_TRUNC, trace_pipe's exclusive and
// consuming reads, the top level's markers copied to an instance,
// set_event, an event's id, filter and enable, eventfs's one inode
// number, trace_options, and rmdir EBUSY while a file is open. Only what
// Linux 7.0 and android17-6.18 share is asked (7.0 has more tracers,
// options and events). As root; the tree's group is put back to 0.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

static int failed;
static char dir[64], inst[128];

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("tracefs: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static long rc(long r) { return r < 0 ? -errno : r; }

static char *at(const char *base, const char *name) {
    static char p[8][256];
    static int k;
    k = (k + 1) % 8;
    snprintf(p[k], sizeof p[k], "%s/%s", base, name);
    return p[k];
}

// The whole of a file, or "" and errno.
static char *slurp(const char *path) {
    static char b[65536];
    int fd = open(path, O_RDONLY);
    b[0] = 0;
    if (fd < 0) return b;
    long n = 0, r;
    while ((r = read(fd, b + n, sizeof b - 1 - n)) > 0) n += r;
    b[n] = 0;
    close(fd);
    return b;
}

static long put(const char *path, const char *s, long len, int flags) {
    int fd = open(path, O_WRONLY | flags);
    if (fd < 0) return -errno;
    long r = rc(write(fd, s, len));
    close(fd);
    return r;
}

static long puts_(const char *path, const char *s) { return put(path, s, strlen(s), 0); }

static void want_text(const char *what, const char *got, const char *expect) {
    if (strcmp(got, expect)) {
        printf("tracefs: %s: want \"%s\", got \"%s\"\n", what, expect, got);
        failed = 1;
    }
}

static void want_has(const char *what, const char *got, const char *part) {
    if (!strstr(got, part)) {
        printf("tracefs: %s: no \"%s\" in \"%.300s\"\n", what, part, got);
        failed = 1;
    }
}

int main(void) {
    snprintf(dir, sizeof dir, "/tmp/tracefs-test-%d", getpid());
    if (mkdir(dir, 0755)) {
        printf("tracefs: mkdir %s: %d\n", dir, errno);
        return 1;
    }
    want("an unknown option", rc(mount("tracefs", dir, "tracefs", 0, "foo=1")), -EINVAL);
    want("a gid that is not a number", rc(mount("tracefs", dir, "tracefs", 0, "gid=abc")), -EINVAL);
    if (mount("tracefs", dir, "tracefs", 0, "gid=3012,mode=700")) {
        printf("tracefs: mount: %d\n", errno);
        rmdir(dir);
        return 1;
    }
    struct statfs sf;
    want("statfs", rc(statfs(dir, &sf)), 0);
    want("its magic", sf.f_type, 0x74726163);
    struct stat st;
    want("stat root", rc(stat(dir, &st)), 0);
    want("root mode", st.st_mode, 040700);
    want("root group", st.st_gid, 3012);
    want("stat trace", rc(stat(at(dir, "trace"), &st)), 0);
    want("trace mode", st.st_mode, 0100640);
    want("trace group", st.st_gid, 3012);
    want("stat trace_marker", rc(stat(at(dir, "trace_marker"), &st)), 0);
    want("trace_marker mode", st.st_mode & 07777, 0220);
    const char *en = strdup(at(dir, "events/sched/sched_switch/enable"));
    want("stat an event's enable", rc(stat(en, &st)), 0);
    want("its mode", st.st_mode, 0100640);
    want("its group", st.st_gid, 3012);
    want("chmod it", rc(chmod(en, 0666)), 0);
    want("stat again", rc(stat(en, &st)), 0);
    want("its mode kept", st.st_mode & 07777, 0666);
    chmod(en, 0640);
    struct stat a, b;
    stat(at(dir, "events/sched/sched_switch/id"), &a);
    stat(at(dir, "events/sched/sched_wakeup/format"), &b);
    want("eventfs files share an inode number", a.st_ino == b.st_ino, 1);
    want("mkdir in events", rc(mkdir(at(dir, "events/foo"), 0755)), -EPERM);
    want("mkdir in the root", rc(mkdir(at(dir, "gexnew"), 0755)), -EPERM);
    want("a new file", rc(open(at(dir, "gexnewfile"), O_WRONLY | O_CREAT, 0644)), -EACCES);
    want("unlink trace", rc(unlink(at(dir, "trace"))), -EPERM);

    // An instance of the test's own.
    snprintf(inst, sizeof inst, "%s/instances/gextest%d", dir, getpid());
    want("mkdir an instance", rc(mkdir(inst, 0700)), 0);
    want("mkdir it again", rc(mkdir(inst, 0700)), -EEXIST);
    want("stat it", rc(stat(inst, &st)), 0);
    want("its mode (the mkdir's is ignored)", st.st_mode & 07777, 0750);
    want("rmdir its events", rc(rmdir(at(inst, "events"))), -EPERM);

    want_text("tracing_on", slurp(at(inst, "tracing_on")), "1\n");
    want_text("buffer_size_kb", slurp(at(inst, "buffer_size_kb")), "1410\n");
    want_text("buffer_percent", slurp(at(inst, "buffer_percent")), "50\n");
    want_has("trace_clock", slurp(at(inst, "trace_clock")), "[local] global counter uptime perf mono mono_raw boot");
    want_text("current_tracer", slurp(at(inst, "current_tracer")), "nop\n");
    want("buffer_size_kb 0", puts_(at(inst, "buffer_size_kb"), "0"), -EINVAL);
    want("buffer_percent 101", puts_(at(inst, "buffer_percent"), "101"), -EINVAL);
    want("an unknown clock", puts_(at(inst, "trace_clock"), "foo"), -EINVAL);
    want("an unknown tracer", puts_(at(inst, "current_tracer"), "foo"), -EINVAL);
    want("an unknown option", puts_(at(inst, "trace_options"), "foo"), -EINVAL);
    char longopt[80];
    memset(longopt, 'a', sizeof longopt);
    want("a 64-byte option", put(at(inst, "trace_options"), longopt, 64, 0), -EINVAL);
    want("options/overwrite 2", puts_(at(inst, "options/overwrite"), "2"), -EINVAL);
    want("buffer_size_kb 1", puts_(at(inst, "buffer_size_kb"), "1"), 1);
    want_text("buffer_size_kb after", slurp(at(inst, "buffer_size_kb")), "7\n");
    want("buffer_size_kb 1408", puts_(at(inst, "buffer_size_kb"), "1408"), 4);
    want("trace_options disable_on_free", puts_(at(inst, "trace_options"), "disable_on_free\n"), 16);
    want_text("options/disable_on_free", slurp(at(inst, "options/disable_on_free")), "1\n");
    char *opts = slurp(at(inst, "trace_options"));
    want_has("a fresh instance's options", opts, "nocopy_trace_marker\n");
    want_has("a fresh instance's options", opts, "notrace_printk_dest\n");
    want_has("a fresh instance's options", opts, "\nmarkers\n");
    want("no options/trace_printk in an instance", rc(access(at(inst, "options/trace_printk"), F_OK)), -ENOENT);

    // trace_marker, as libcutils writes it.
    const char *tr = strdup(at(inst, "trace")), *mk = strdup(at(inst, "trace_marker"));
    want("open trace O_TRUNC", put(tr, "", 0, O_TRUNC), 0);
    want_has("an empty trace", slurp(tr), "# entries-in-buffer/entries-written: 0/0   #P:");
    want("a marker", puts_(mk, "B|42|hello"), 10);
    want("a marker ending in a newline", puts_(mk, "E|42\n"), 5);
    char *t = slurp(tr);
    want_has("trace", t, "# tracer: nop\n#\n# entries-in-buffer/entries-written: 2/2   #P:");
    want_has("trace", t, "#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION\n");
    want_has("trace", t, "...1.");
    want_has("trace", t, ": tracing_mark_write: B|42|hello\n");
    want_has("trace", t, ": tracing_mark_write: E|42\n");
    want("one newline only", strstr(t, "E|42\n\n") == NULL, 1);
    static char big[5000];
    memset(big, 'x', sizeof big);
    want("a 5000-byte marker", put(mk, big, sizeof big, 0), 4054);
    int fd = open(mk, O_WRONLY);
    want("lseek a marker", rc(lseek(fd, 0, SEEK_SET)), -ESPIPE);
    want("pwrite a marker", rc(pwrite(fd, "x", 1, 0)), -ESPIPE);
    close(fd);
    fd = open(mk, O_RDWR);
    char c;
    want("read a marker", rc(read(fd, &c, 1)), -EINVAL);
    close(fd);
    want("tracing_on 0", puts_(at(inst, "tracing_on"), "0"), 1);
    want("a marker with tracing off", puts_(mk, "x"), -EBADF);
    want("tracing_on 1", puts_(at(inst, "tracing_on"), "1"), 1);
    want("nomarkers", puts_(at(inst, "trace_options"), "nomarkers"), 9);
    want("a marker with markers off", puts_(mk, "x"), -EINVAL);
    want("a raw marker with markers off", put(at(inst, "trace_marker_raw"), "abcd", 4, 0), -EINVAL);
    want("markers", puts_(at(inst, "trace_options"), "markers"), 7);
    want("a 3-byte raw marker", put(at(inst, "trace_marker_raw"), "abc", 3, 0), -EINVAL);
    want("a 4097-byte raw marker", put(at(inst, "trace_marker_raw"), big, 4097, 0), -EINVAL);
    want("a raw marker", put(at(inst, "trace_marker_raw"), "\x01\0\0\0hi", 6, 0), 6);

    // trace_pipe: one reader, consuming, a stream.
    want("clear", put(tr, "", 0, O_TRUNC), 0);
    int p1 = open(at(inst, "trace_pipe"), O_RDONLY | O_NONBLOCK);
    want("open trace_pipe", p1 >= 0, 1);
    want("open it twice", rc(open(at(inst, "trace_pipe"), O_RDONLY)), -EBUSY);
    want("a cpu's pipe beside it", rc(open(at(inst, "per_cpu/cpu0/trace_pipe"), O_RDONLY)), -EBUSY);
    char pb[4096];
    want("read an empty pipe", rc(read(p1, pb, sizeof pb)), -EAGAIN);
    want("lseek the pipe", rc(lseek(p1, 0, SEEK_SET)), -ESPIPE);
    want("rmdir with a file open", rc(rmdir(inst)), -EBUSY);
    puts_(mk, "piped");
    long n = rc(read(p1, pb, sizeof pb - 1));
    pb[n > 0 ? n : 0] = 0;
    want_has("the pipe", pb, ": tracing_mark_write: piped\n");
    want("no header in the pipe", strstr(pb, "# tracer") == NULL, 1);
    want("consumed", rc(read(p1, pb, sizeof pb)), -EAGAIN);
    close(p1);

    // The top level's markers, copied to an instance that asks.
    want("copy_trace_marker", puts_(at(inst, "options/copy_trace_marker"), "1"), 1);
    want("a top-level marker", puts_(at(dir, "trace_marker"), "gex-copied"), 10);
    want_has("copied", slurp(tr), "tracing_mark_write: gex-copied\n");
    want("no copy_trace_marker", puts_(at(inst, "options/copy_trace_marker"), "0"), 1);

    // Events.
    want_text("ftrace/print's id", slurp(at(inst, "events/ftrace/print/id")), "5\n");
    want("ftrace/print has no enable", rc(access(at(inst, "events/ftrace/print/enable"), F_OK)), -ENOENT);
    char id[16];
    snprintf(id, sizeof id, "%s", slurp(at(inst, "events/sched/sched_switch/id")));
    char idline[32];
    snprintf(idline, sizeof idline, "\nID: %d\n", atoi(id));
    want_has("format's id", slurp(at(inst, "events/sched/sched_switch/format")), idline);
    want_has("format", slurp(at(inst, "events/sched/sched_switch/format")), "name: sched_switch\n");
    want_text("filter", slurp(at(inst, "events/sched/sched_switch/filter")), "none\n");
    want_text("enable", slurp(at(inst, "events/sched/sched_switch/enable")), "0\n");
    want("set_event nosuch", puts_(at(inst, "set_event"), "gexnosuch:event"), -EINVAL);
    want("set_event sched:sched_switch", puts_(at(inst, "set_event"), "sched:sched_switch"), 18);
    want_text("set_event", slurp(at(inst, "set_event")), "sched:sched_switch\n");
    want_text("enable now", slurp(at(inst, "events/sched/sched_switch/enable")), "1\n");
    want_text("sched's enable", slurp(at(inst, "events/sched/enable")), "X\n");
    want("enable 2", puts_(at(inst, "events/sched/sched_switch/enable"), "2"), -EINVAL);
    want("set_event O_TRUNC", put(at(inst, "set_event"), "", 0, O_TRUNC), 0);
    want_text("set_event cleared", slurp(at(inst, "set_event")), "");
    want_text("sched's enable after", slurp(at(inst, "events/sched/enable")), "0\n");

    want("rmdir the instance", rc(rmdir(inst)), 0);
    want("it is gone", rc(access(inst, F_OK)), -ENOENT);
    // The tree's group back as it was.
    want("umount", rc(umount(dir)), 0);
    want("mount gid=0", rc(mount("tracefs", dir, "tracefs", 0, "gid=0")), 0);
    want("umount again", rc(umount(dir)), 0);
    want("rmdir", rc(rmdir(dir)), 0);
    if (!failed) printf("tracefs ok\n");
    return failed;
}
