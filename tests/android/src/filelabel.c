// The SELinux labels of files: the security.selinux attribute, read and
// set, what a new file is given, and what an execve makes of a program's.
//
// - In a filesystem labelled by transition (tmpfs, in the policy used
//   here) a new file or directory is labelled as the directory it is made
//   in, unless its maker asked otherwise (fscreate) or the policy has a
//   transition for the maker, the directory, the class and the name.
// - getxattr reads a file's context and the NUL that ends it; the size
//   alone for no buffer, ERANGE for a short one. listxattr names it.
// - setxattr relabels: a context, an alias of one (read back as the type
//   it names); by root one the policy has no words for, read back as
//   written; nothing at all is EINVAL, XATTR_CREATE is EEXIST (there is
//   always one), and removexattr is EACCES.
// - A label is the file's: it follows a rename and is a hard link's too.
// - proc and selinuxfs are labelled by the policy's genfscon rules and
//   take no labels (EOPNOTSUPP); a pipe is its maker's.
// - An execve by a process that asked for nothing makes it what the
//   policy has for it and the program's label, or leaves it as it was.
//
// The policy is the kernel crate's labels.33 (its test policy with tmpfs
// labelled by transition), built in and loaded into the kernel the
// program runs on: on Linux this wants a machine kept for it, booted with
// SELinux on and not enforcing.
//
// Needs root, selinuxfs and tmpfs; without them the program says so and
// exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef LABELS_POLICY
#error "build with -DLABELS_POLICY=\"<path to labels.33>\""
#endif
__asm__(".section .rodata\n"
        ".global labels_policy\n"
        "labels_policy:\n"
        ".incbin \"" LABELS_POLICY "\"\n"
        ".global labels_policy_end\n"
        "labels_policy_end:\n"
        ".previous\n");
extern const char labels_policy[], labels_policy_end[];

#define X "security.selinux"
#define FILE_T "system_u:object_r:file_t:s0"
#define EXEC_T "system_u:object_r:exec_t:s0"
#define TMP_T "system_u:object_r:tmp_t:s0"
#define KERNEL_T "system_u:system_r:kernel_t:s0"
#define INIT_T "system_u:system_r:init_t:s0"
#define APP_T "system_u:system_r:app_t:s0"

static char dir[64], sel[80];

static void die(const char *what, long a, long b) {
    printf("filelabel: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    umount2(dir, MNT_DETACH);
    rmdir(dir);
    exit(1);
}

static const char *in(const char *name) {
    static char path[4][160];
    static int at;
    char *p = path[at++ & 3];
    snprintf(p, 160, "%s/%s", dir, name);
    return p;
}

// A file's label is this context and its NUL; the link's own with nofollow.
static void labelled_at(const char *path, const char *want, int nofollow) {
    char buf[256];
    long n = nofollow ? lgetxattr(path, X, buf, sizeof buf - 1) : getxattr(path, X, buf, sizeof buf - 1);
    if (n < 0) die(path, n, 0);
    buf[n] = 0;
    long len = strlen(want) + 1;
    if (n != len || memcmp(buf, want, len)) {
        printf("filelabel: %s is labelled '%s' in %ld bytes, not '%s' in %ld\n", path, buf, n, want, len);
        die("a label", n, len);
    }
}

static void labelled(const char *name, const char *want) {
    labelled_at(in(name), want, 0);
}

// Set a file's label to n bytes: 0, or the errno.
static int relabel(const char *name, const char *value, size_t n, int flags) {
    return setxattr(in(name), X, value, n, flags) ? errno : 0;
}

static void touch(const char *name) {
    int fd = open(in(name), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0755);
    if (fd < 0) die(name, 0, 0);
    close(fd);
}

static void attr(const char *name, const char *value) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/attr/%s", name);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0 || write(fd, value, strlen(value)) != (long)strlen(value)) die(path, 0, 0);
    close(fd);
}

static void attr_is(const char *name, const char *want) {
    char path[64], buf[256];
    snprintf(path, sizeof path, "/proc/self/attr/%s", name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    long n = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
    if (n < 0) die(path, 0, 0);
    buf[n] = 0;
    close(fd);
    if (strcmp(buf, want)) {
        printf("filelabel: %s is '%s', not '%s'\n", path, buf, want);
        die("a process's context", 0, 0);
    }
}

static void wait_ok(pid_t pid, const char *what) {
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) die(what, st, 0);
}

// This program's own file, copied to `name` in the tmpfs, to be run.
static void copy_self(const char *name) {
    int from = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    int to = open(in(name), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0755);
    if (from < 0 || to < 0) die("copying the program", from, to);
    static char buf[1 << 16];
    for (long n; (n = read(from, buf, sizeof buf)) > 0;)
        if (write(to, buf, n) != n) die("copying the program", n, 0);
    close(from);
    close(to);
}

int main(int argc, char **argv) {
    // Run again from a labelled copy: say what this process now is.
    if (argc == 4 && !strcmp(argv[1], "after-exec")) {
        attr_is("current", argv[2]);
        attr_is("prev", argv[3]);
        return 0;
    }
    if (geteuid() != 0) {
        printf("filelabel: not root, cannot load a policy\n");
        return 77;
    }
    snprintf(dir, sizeof dir, "/tmp/filelabel-test-%d", getpid());
    snprintf(sel, sizeof sel, "%s-selinuxfs", dir);
    if (mkdir(dir, 0755) || mkdir(sel, 0755)) die("mkdir", 0, 0);
    if (mount("selinuxfs", sel, "selinuxfs", 0, NULL)) {
        printf("filelabel: cannot mount selinuxfs: errno %d\n", errno);
        rmdir(dir);
        rmdir(sel);
        return errno == EPERM || errno == ENODEV || errno == EACCES ? 77 : 1;
    }
    char path[160];
    snprintf(path, sizeof path, "%s/load", sel);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    long size = labels_policy_end - labels_policy;
    if (fd < 0 || write(fd, labels_policy, size) != size) die("load", size, 0);
    close(fd);
    if (mount("none", dir, "tmpfs", 0, NULL)) die("mount tmpfs", 0, 0);
    attr_is("current", KERNEL_T);

    // What is made in it, by a process of the kernel's context.
    labelled("", TMP_T);
    touch("a");
    labelled("a", TMP_T);
    if (mkdir(in("dir"), 0755)) die("mkdir", 0, 0);
    labelled("dir", TMP_T);
    if (symlink("a", in("lnk"))) die("symlink", 0, 0);
    labelled_at(in("lnk"), TMP_T, 1);
    labelled("lnk", TMP_T);

    // Reading the attribute.
    char buf[256];
    if (getxattr(in("a"), X, NULL, 0) != 27) die("the label's size", errno, 27);
    if (getxattr(in("a"), X, buf, 5) != -1 || errno != ERANGE) die("a short buffer", errno, ERANGE);
    long n = listxattr(in("a"), buf, sizeof buf);
    if (n != sizeof X || memcmp(buf, X, sizeof X)) die("the list of attributes", n, sizeof X);
    if (getxattr(in("nothing"), X, buf, sizeof buf) != -1 || errno != ENOENT) die("the label of nothing", errno, ENOENT);

    // Relabelling.
    if (relabel("a", EXEC_T, 27, 0)) die("relabel", errno, 0);
    labelled("a", EXEC_T);
    if (relabel("a", FILE_T, 28, 0)) die("relabel with the NUL", errno, 0);
    labelled("a", FILE_T);
    if (relabel("a", "system_u:object_r:old_file_t:s0", 31, 0)) die("relabel by an alias", errno, 0);
    labelled("a", FILE_T);
    // Root may write what the policy has no words for, and reads it back.
    if (relabel("a", FILE_T "\n", 28, 0)) die("relabel with a newline", errno, 0);
    labelled("a", FILE_T "\n");
    if (relabel("a", "nobody:object_r:file_t:s0", 25, 0)) die("relabel to no user's context", errno, 0);
    labelled("a", "nobody:object_r:file_t:s0");
    if (relabel("a", "junk", 4, 0)) die("relabel to junk", errno, 0);
    labelled("a", "junk");
    if (relabel("a", "", 0, 0) != EINVAL) die("relabel to nothing", errno, EINVAL);
    if (relabel("a", EXEC_T, 27, XATTR_CREATE) != EEXIST) die("XATTR_CREATE of a label", errno, EEXIST);
    labelled("a", "junk");
    if (relabel("a", EXEC_T, 27, XATTR_REPLACE)) die("XATTR_REPLACE of a label", errno, 0);
    labelled("a", EXEC_T);
    if (relabel("a", "system_u:object_r:file_t:s0-s1:c0.c2", 36, 0)) die("relabel to a range", errno, 0);
    labelled("a", "system_u:object_r:file_t:s0-s1:c0.c2");
    if (relabel("a", KERNEL_T, 29, 0)) die("relabel to a process's context", errno, 0);
    labelled("a", KERNEL_T);
    if (removexattr(in("a"), X) != -1 || errno != EACCES) die("a label removed", errno, EACCES);
    labelled("a", KERNEL_T);
    // A symbolic link is a class this policy has not.
    if (lsetxattr(in("lnk"), X, EXEC_T, 27, 0) != -1 || errno != EINVAL) die("a link relabelled", errno, EINVAL);

    // A directory's label is what is made in it; a label follows its file.
    if (relabel("dir", EXEC_T, 27, 0)) die("relabel a directory", errno, 0);
    touch("dir/in");
    labelled("dir/in", EXEC_T);
    if (rename(in("a"), in("dir/moved"))) die("rename", 0, 0);
    labelled("dir/moved", KERNEL_T);
    if (link(in("dir/moved"), in("hard"))) die("link", 0, 0);
    labelled("hard", KERNEL_T);
    if (relabel("hard", FILE_T, 27, 0)) die("relabel by a link", errno, 0);
    labelled("dir/moved", FILE_T);

    // What a process asks its files to be, until it takes that back.
    attr("fscreate", EXEC_T);
    touch("fc");
    labelled("fc", EXEC_T);
    if (mkdir(in("fcd"), 0755)) die("mkdir", 0, 0);
    labelled("fcd", EXEC_T);
    touch("fc-again");
    labelled("fc-again", EXEC_T);
    attr("fscreate", "\n");
    touch("fc-after");
    labelled("fc-after", TMP_T);

    // The policy's transitions by name, for a process of app_t.
    pid_t pid = fork();
    if (pid < 0) die("fork", 0, 0);
    if (pid == 0) {
        attr("current", APP_T);
        touch("special");
        labelled("special", FILE_T);
        touch("plain");
        labelled("plain", TMP_T);
        if (mkdir(in("other"), 0755) || mkdir(in("plaindir"), 0755)) die("mkdir", 0, 0);
        labelled("other", EXEC_T);
        labelled("plaindir", TMP_T);
        touch("dir/special");
        labelled("dir/special", EXEC_T);
        _exit(0);
    }
    wait_ok(pid, "the process of app_t");

    // Another attribute of the kernel's namespace, which root may keep
    // here, and one of the user's.
    if (setxattr(in("fc"), "security.other", "1", 1, 0) || setxattr(in("fc"), "user.x", "1", 1, 0)) die("other attributes", errno, 0);
    n = listxattr(in("fc"), buf, sizeof buf);
    int seen = 0;
    for (long at = 0; at < n; at += strlen(buf + at) + 1) seen += !strcmp(buf + at, X) + 10 * !strcmp(buf + at, "security.other") + 100 * !strcmp(buf + at, "user.x");
    if (seen != 111) die("the list with other attributes", seen, n);

    // Filesystems the policy labels by genfscon, which take no labels.
    labelled_at("/proc/cpuinfo", FILE_T, 0);
    labelled_at("/proc/sys/kernel/osrelease", EXEC_T, 0);
    labelled_at("/proc/sys/kernel", TMP_T, 0);
    if (setxattr("/proc/cpuinfo", X, FILE_T, 27, 0) != -1 || errno != EOPNOTSUPP) die("a file of proc relabelled", errno, EOPNOTSUPP);
    n = listxattr("/proc/cpuinfo", buf, sizeof buf);
    if (n != sizeof X || memcmp(buf, X, sizeof X)) die("the attributes of a file of proc", n, sizeof X);
    snprintf(path, sizeof path, "%s/enforce", sel);
    labelled_at(path, TMP_T, 0);
    if (setxattr(path, X, FILE_T, 27, 0) != -1 || errno != EOPNOTSUPP) die("a file of selinuxfs relabelled", errno, EOPNOTSUPP);
    snprintf(path, sizeof path, "%s/null", sel);
    labelled_at(path, TMP_T, 0);

    // A pipe is its maker's, and of a class this policy has not.
    int p[2];
    if (pipe2(p, O_CLOEXEC)) die("pipe", 0, 0);
    n = fgetxattr(p[0], X, buf, sizeof buf);
    if (n != 30 || strcmp(buf, KERNEL_T)) die("a pipe's label", n, 30);
    if (fsetxattr(p[0], X, FILE_T, 27, 0) != -1 || errno != EINVAL) die("a pipe relabelled", errno, EINVAL);

    // An execve: this policy makes init_t running exec_t app_t, in
    // another role and at another level; any other program leaves a
    // process what it was.
    copy_self("prog");
    labelled("prog", TMP_T);
    for (int labelled_exec = 0; labelled_exec < 2; labelled_exec++) {
        if (labelled_exec && relabel("prog", EXEC_T, 27, 0)) die("relabel the program", errno, 0);
        pid = fork();
        if (pid < 0) die("fork", 0, 0);
        if (pid == 0) {
            attr("current", INIT_T);
            char *args[] = {"prog", "after-exec", labelled_exec ? "system_u:app_r:app_t:s1:c0,c1" : INIT_T, INIT_T, NULL};
            execv(in("prog"), args);
            die("execv", 0, 0);
        }
        wait_ok(pid, labelled_exec ? "the program run as exec_t" : "the program run as tmp_t");
    }

    if (umount(dir) || umount(sel)) die("umount", 0, 0);
    rmdir(dir);
    rmdir(sel);
    printf("filelabel ok\n");
    return 0;
}
