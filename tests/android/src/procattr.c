// A process's SELinux attributes, the files of /proc/<pid>/attr: what
// libselinux's getcon, setcon, setexeccon and setfscreatecon read and
// write.
//
// - current is the context the process runs as, prev the one it had
//   before its last execve. exec, fscreate, keycreate and sockcreate are
//   requests: empty until made, a context and its NUL after.
// - A write sets one from the file's start: a newline at the end is not
//   part of the context nor counted in what the write returns; nothing,
//   or a NUL or a newline first, takes the request back. prev cannot be
//   set, current cannot be taken back, and text that is no context is
//   EINVAL (but for fscreate, by a process that may ask for a context the
//   policy lacks).
// - Only the process itself writes them: not through another's /proc
//   directory, and not through a descriptor it was left by its parent.
// - A fork has its parent's; an execve makes the process what it asked to
//   be, with what it was as prev, and forgets every request.
// - A stream socket's peer is known by the context its socket was made
//   as (SO_PEERSEC): its maker's, or what the maker asked for its sockets.
//
// The policy is the kernel crate's test policy, built in and loaded into
// the kernel the program runs on, as selinuxfs.c does: on Linux this
// wants a machine kept for it, booted with SELinux on and not enforcing.
//
// Needs root and selinuxfs; without them the program says so and exits
// 77.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TEST_POLICY
#error "build with -DTEST_POLICY=\"<path to test.33>\""
#endif
__asm__(".section .rodata\n"
        ".global test_policy\n"
        "test_policy:\n"
        ".incbin \"" TEST_POLICY "\"\n"
        ".global test_policy_end\n"
        "test_policy_end:\n"
        ".previous\n");
extern const char test_policy[], test_policy_end[];

#define FILE_T "system_u:object_r:file_t:s0"
#define KERNEL_T "system_u:system_r:kernel_t:s0"
#define INIT_T "system_u:system_r:init_t:s0"
#define APP_T "system_u:system_r:app_t:s0"

static void die(const char *what, long a, long b) {
    printf("procattr: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *attr(const char *name) {
    static char path[4][96];
    static int at;
    char *p = path[at++ & 3];
    snprintf(p, 96, "/proc/self/attr/%s", name);
    return p;
}

// A file reads this context and its NUL, or nothing for "".
static void reads_at(const char *path, const char *want) {
    char buf[256];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) die(path, 0, 0);
    long n = read(fd, buf, sizeof buf - 1);
    if (n < 0) die(path, n, 0);
    buf[n] = 0;
    long len = *want ? (long)strlen(want) + 1 : 0;
    if (n != len || memcmp(buf, want, n)) {
        printf("procattr: %s reads '%s' in %ld bytes, not '%s' in %ld\n", path, buf, n, want, len);
        exit(1);
    }
    if (read(fd, buf, sizeof buf) != 0) die("an attribute read past its end", 0, 0);
    close(fd);
}

static void reads(const char *name, const char *want) {
    reads_at(attr(name), want);
}

// Write n bytes to an attribute: what the write returned, or -errno.
static long put_n(const char *name, const char *text, size_t n) {
    int fd = open(attr(name), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    long r = write(fd, text, n);
    if (r < 0) r = -errno;
    close(fd);
    return r;
}

static long put(const char *name, const char *text) {
    return put_n(name, text, strlen(text));
}

static void puts_and_reads(const char *name, const char *text, size_t n, long returns, const char *then) {
    long r = put_n(name, text, n);
    if (r != returns) {
        printf("procattr: writing %zu bytes to %s returned %ld, not %ld\n", n, name, r, returns);
        exit(1);
    }
    reads(name, then);
}

static void load_policy(void) {
    char dir[64];
    snprintf(dir, sizeof dir, "/tmp/procattr-test-%d", getpid());
    if (mkdir(dir, 0755)) die("mkdir", 0, 0);
    if (mount("selinuxfs", dir, "selinuxfs", 0, NULL)) {
        printf("procattr: cannot mount selinuxfs: errno %d\n", errno);
        rmdir(dir);
        exit(errno == EPERM || errno == ENODEV || errno == EACCES ? 77 : 1);
    }
    char path[96];
    snprintf(path, sizeof path, "%s/class/file", dir);
    if (access(path, F_OK)) {
        // No policy yet: every process is "kernel", and whatever it asks
        // to be is the kernel's SID too.
        reads("current", "kernel");
        reads("prev", "kernel");
        reads("exec", "");
        if (put("exec", "anything") != 8) die("a request before a policy", errno, 0);
        reads("exec", "kernel");
        if (put("exec", "") != 0) die("a request taken back before a policy", errno, 0);
    }
    snprintf(path, sizeof path, "%s/load", dir);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    long size = test_policy_end - test_policy;
    if (fd < 0 || write(fd, test_policy, size) != size) die("load", size, 0);
    close(fd);
    if (umount(dir)) die("umount", 0, 0);
    rmdir(dir);
}

// After an execve that asked to be init_t with requests outstanding.
static int after_exec(const char *asked) {
    if (!strcmp(asked, "asked")) {
        reads("current", INIT_T);
        reads("prev", KERNEL_T);
    } else {
        // Nothing asked: it is what it was.
        reads("current", APP_T);
        reads("prev", APP_T);
    }
    reads("exec", "");
    reads("fscreate", "");
    reads("keycreate", "");
    reads("sockcreate", "");
    return 0;
}

// Run this program again as `how`, and wait for it.
static void run_again(const char *how) {
    char *argv[] = {"procattr", "after-exec", (char *)how, NULL};
    execv("/proc/self/exe", argv);
    die("execv", 0, 0);
}

static void wait_ok(pid_t pid, const char *what) {
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) die(what, st, 0);
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "after-exec")) return after_exec(argv[2]);
    if (geteuid() != 0) {
        printf("procattr: not root, cannot load a policy\n");
        return 77;
    }
    load_policy();

    // The directory and its files.
    int seen = 0;
    DIR *d = opendir("/proc/self/attr");
    if (!d) die("opendir", 0, 0);
    for (struct dirent *e; (e = readdir(d));)
        for (int i = 0; i < 6; i++) seen += !strcmp(e->d_name, (const char *[]){"current", "prev", "exec", "fscreate", "keycreate", "sockcreate"}[i]);
    closedir(d);
    if (seen != 6) die("the names in attr", seen, 6);
    struct stat st;
    if (stat("/proc/self/attr", &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 0777) != 0555) die("attr", st.st_mode, 0);
    if (stat(attr("current"), &st) || !S_ISREG(st.st_mode) || (st.st_mode & 0777) != 0666 || st.st_size) die("current's node", st.st_mode, st.st_size);
    if (stat(attr("exec"), &st) || (st.st_mode & 0777) != 0666) die("exec's node", st.st_mode, 0);
    if (stat(attr("prev"), &st) || (st.st_mode & 0777) != 0444) die("prev's node", st.st_mode, 0);
    if (open(attr("nothing"), O_RDONLY) != -1 || errno != ENOENT) die("a name that is not there", errno, ENOENT);

    reads("current", KERNEL_T);
    reads("prev", KERNEL_T);
    reads("exec", "");
    reads("fscreate", "");
    reads("keycreate", "");
    reads("sockcreate", "");
    // The same files by the process's number, and by its thread's.
    char path[96];
    snprintf(path, sizeof path, "/proc/%d/attr/current", getpid());
    reads_at(path, KERNEL_T);
    snprintf(path, sizeof path, "/proc/self/task/%d/attr/current", gettid());
    reads_at(path, KERNEL_T);

    // Requests: made, made again, refused, taken back.
    puts_and_reads("exec", INIT_T, 27, 27, INIT_T);
    puts_and_reads("exec", INIT_T "\n", 28, 27, INIT_T);
    puts_and_reads("exec", INIT_T "\0", 28, 28, INIT_T);
    puts_and_reads("exec", "nobody:system_r:init_t:s0", 25, -EINVAL, INIT_T);
    puts_and_reads("exec", "", 0, 0, "");
    puts_and_reads("exec", INIT_T, 27, 27, INIT_T);
    puts_and_reads("exec", "\n", 1, 1, "");
    puts_and_reads("exec", INIT_T, 27, 27, INIT_T);
    puts_and_reads("exec", "\0", 1, 1, "");
    puts_and_reads("fscreate", FILE_T, 27, 27, FILE_T);
    puts_and_reads("fscreate", "\0", 1, 1, "");
    puts_and_reads("sockcreate", FILE_T, 27, 27, FILE_T);
    puts_and_reads("sockcreate", "", 0, 0, "");
    puts_and_reads("keycreate", FILE_T, 27, 27, FILE_T);
    puts_and_reads("keycreate", "\n", 1, 1, "");
    puts_and_reads("prev", KERNEL_T, 29, -EOPNOTSUPP, KERNEL_T);
    // Root may ask that the files it makes have a context the policy has
    // no words for; it reads as unlabeled, which this policy has as
    // file_t.
    puts_and_reads("fscreate", "nobody:system_r:init_t:s0", 25, 25, FILE_T);
    puts_and_reads("fscreate", "", 0, 0, "");

    // One open file: written from the start as often as wanted (a write
    // does not move the position), read from there, and not written
    // anywhere else.
    int fd = open(attr("exec"), O_RDWR | O_CLOEXEC);
    if (fd < 0) die("open exec", 0, 0);
    if (write(fd, APP_T, 26) != 26 || write(fd, INIT_T, 27) != 27) die("exec written twice", errno, 0);
    char buf[64];
    if (read(fd, buf, sizeof buf) != 28 || strcmp(buf, INIT_T)) die("exec read after its writes", buf[0], 0);
    if (write(fd, INIT_T, 27) != -1 || errno != EINVAL) die("exec written after a read", errno, EINVAL);
    if (pwrite(fd, INIT_T, 27, 1) != -1 || errno != EINVAL) die("exec written past the start", errno, EINVAL);
    if (pwrite(fd, "", 0, 0) != 0) die("exec taken back", errno, 0);
    reads("exec", "");

    // A fork has its parent's, and only itself to change.
    if (put("exec", INIT_T) != 27 || put("fscreate", FILE_T) != 27) die("requests before a fork", errno, 0);
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) die("fork", 0, 0);
    if (pid == 0) {
        reads("current", KERNEL_T);
        reads("exec", INIT_T);
        reads("fscreate", FILE_T);
        // Its own.
        if (put("exec", APP_T) != 26) die("a child's own request", errno, 0);
        reads("exec", APP_T);
        // Its parent's: read, and not written, by name or by the
        // descriptor the parent left it.
        snprintf(path, sizeof path, "/proc/%d/attr/exec", parent);
        reads_at(path, INIT_T);
        snprintf(path, sizeof path, "/proc/%d/attr/current", parent);
        reads_at(path, KERNEL_T);
        snprintf(path, sizeof path, "/proc/%d/attr/exec", parent);
        int other = open(path, O_WRONLY | O_CLOEXEC);
        if (other < 0) die("a parent's exec opened", 0, 0);
        if (write(other, APP_T, 26) != -1 || errno != EPERM) die("a parent's exec written by name", errno, EPERM);
        if (pwrite(fd, APP_T, 26, 0) != -1 || errno != EPERM) die("a parent's exec written by its descriptor", errno, EPERM);
        _exit(0);
    }
    wait_ok(pid, "the forked child");
    reads("exec", INIT_T);

    // An execve: what was asked, what it was as prev, nothing asked after.
    if (put("keycreate", FILE_T) != 27 || put("sockcreate", FILE_T) != 27) die("requests before an exec", errno, 0);
    pid = fork();
    if (pid < 0) die("fork", 0, 0);
    if (pid == 0) run_again("asked");
    wait_ok(pid, "the program run again as init_t");
    // The parent's requests are its own still.
    reads("exec", INIT_T);
    reads("keycreate", FILE_T);
    if (put("exec", "") || put("fscreate", "") || put("keycreate", "") || put("sockcreate", "")) die("requests taken back", errno, 0);

    // setcon: current changes and prev does not; no context is EINVAL,
    // and so is none at all.
    puts_and_reads("current", "system_u:object_r:old_file_t:s0", 31, 31, FILE_T);
    puts_and_reads("current", "junk", 4, -EINVAL, FILE_T);
    puts_and_reads("current", "", 0, -EINVAL, FILE_T);
    puts_and_reads("current", "\n", 1, -EINVAL, FILE_T);
    puts_and_reads("current", APP_T, 26, 26, APP_T);
    reads("prev", KERNEL_T);
    // And an execve that asked for nothing leaves it what it is (this
    // policy has no transition for app_t and this program's label).
    pid = fork();
    if (pid < 0) die("fork", 0, 0);
    if (pid == 0) run_again("kept");
    wait_ok(pid, "the program run again as it was");
    puts_and_reads("current", KERNEL_T, 29, 29, KERNEL_T);

    // What a socket's peer is (SO_PEERSEC, libselinux's getpeercon): the
    // context of the socket at the far end of a stream, which is its
    // maker's unless the maker asked otherwise for its sockets.
    int sv[2];
    char ctx[128];
    socklen_t len = sizeof ctx;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) die("socketpair", 0, 0);
    if (getsockopt(sv[0], SOL_SOCKET, SO_PEERSEC, ctx, &len)) die("SO_PEERSEC", errno, 0);
    if (len != sizeof KERNEL_T || memcmp(ctx, KERNEL_T, sizeof KERNEL_T)) die("a peer's context", len, sizeof KERNEL_T);
    len = 4;
    if (getsockopt(sv[1], SOL_SOCKET, SO_PEERSEC, ctx, &len) != -1 || errno != ERANGE || len != sizeof KERNEL_T) die("SO_PEERSEC into a short buffer", errno, len);
    close(sv[0]);
    close(sv[1]);
    if (put("sockcreate", FILE_T) != 27) die("a request for sockets", errno, 0);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) die("socketpair", 0, 0);
    len = sizeof ctx;
    if (getsockopt(sv[0], SOL_SOCKET, SO_PEERSEC, ctx, &len) || len != sizeof FILE_T || memcmp(ctx, FILE_T, sizeof FILE_T)) die("the peer of a socket asked for", errno, len);
    close(sv[0]);
    close(sv[1]);
    if (put("sockcreate", "")) die("the request taken back", errno, 0);
    // A datagram socket has no such peer.
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv)) die("socketpair", 0, 0);
    len = sizeof ctx;
    if (getsockopt(sv[0], SOL_SOCKET, SO_PEERSEC, ctx, &len) != -1 || errno != ENOPROTOOPT) die("SO_PEERSEC of a datagram socket", errno, ENOPROTOOPT);
    close(sv[0]);
    close(sv[1]);

    printf("procattr ok\n");
    return 0;
}
