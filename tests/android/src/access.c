// access and faccessat as fs/open.c's do_faccessat asks: the real ids
// (the effective ones with AT_EACCESS), root's permitted capabilities and
// nobody else's; EROFS for a write to a read-only filesystem; then the
// owner's, the group's or the others' bits (fs/namei.c's
// generic_permission), and what CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH
// let root past: everything on a directory, a file's read and write, and
// its execute only where some execute bit is set. Android's ART refuses to
// load code a process could write, by asking access(W_OK). Run as root.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failed;
static char base[] = "/tmp/access-XXXXXX";

static void want(const char *what, int r, int err) {
    int got = r == 0 ? 0 : errno;
    if (got != err) {
        printf("access: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

static const char *at(const char *name) {
    static char p[4][128];
    static int i;
    i = (i + 1) % 4;
    snprintf(p[i], sizeof p[i], "%s/%s", base, name);
    return p[i];
}

static void make(const char *name, mode_t mode, uid_t uid, gid_t gid, int dir) {
    const char *p = at(name);
    if (dir ? mkdir(p, 0700) : close(open(p, O_CREAT | O_WRONLY, 0600))) {
        printf("access: making %s (errno %d)\n", name, errno);
        exit(1);
    }
    if (chown(p, uid, gid) || chmod(p, mode)) {
        printf("access: owning %s (errno %d)\n", name, errno);
        exit(1);
    }
}

int main(void) {
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, "mode=0755")) {
        printf("access: tmpfs (errno %d)\n", errno);
        return 1;
    }
    make("root644", 0644, 0, 0, 0);
    make("root600", 0600, 0, 0, 0);
    make("root000", 0000, 0, 0, 0);
    make("root755", 0755, 0, 0, 0);
    make("mine640", 0640, 1000, 1000, 0);
    make("group460", 0460, 0, 3003, 0);
    make("other604", 0604, 0, 0, 0);
    make("dir700", 0700, 0, 0, 1);
    make("dir000", 0000, 0, 0, 1);

    // Root: CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH.
    want("root, write 644", access(at("root644"), W_OK), 0);
    want("root, read 000", access(at("root000"), R_OK), 0);
    want("root, write 000", access(at("root000"), W_OK), 0);
    want("root, execute 644", access(at("root644"), X_OK), EACCES);
    want("root, execute 755", access(at("root755"), X_OK), 0);
    want("root, everything on dir 000", access(at("dir000"), R_OK | W_OK | X_OK), 0);
    want("a mode past the bits", access(at("root644"), 8), EINVAL);
    want("not there", access(at("nothing"), F_OK), ENOENT);
    want("there", access(at("root000"), F_OK), 0);
    want("a flag not known", syscall(SYS_faccessat2, AT_FDCWD, at("root644"), R_OK, 0x8000), EINVAL);

    pid_t child = fork();
    if (child == 0) {
        gid_t groups[] = {3003};
        if (setgroups(1, groups) || setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) _exit(2);
        failed = 0;
        want("1000, read root 644", access(at("root644"), R_OK), 0);
        want("1000, write root 644", access(at("root644"), W_OK), EACCES);
        want("1000, read root 600", access(at("root600"), R_OK), EACCES);
        want("1000, read and write its 640", access(at("mine640"), R_OK | W_OK), 0);
        want("1000, execute its 640", access(at("mine640"), X_OK), EACCES);
        want("1000, by its group, read and write 460", access(at("group460"), R_OK | W_OK), 0);
        want("1000, others' bits, read 604", access(at("other604"), R_OK), 0);
        want("1000, others' bits, write 604", access(at("other604"), W_OK), EACCES);
        want("1000, read dir 700", access(at("dir700"), R_OK), EACCES);
        want("1000, search dir 700", access(at("dir700"), X_OK), EACCES);
        want("1000, there", access(at("root600"), F_OK), 0);
        fflush(stdout);
        _exit(failed);
    }
    int st;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) {
        printf("access: the unprivileged child (status %#x)\n", st);
        failed = 1;
    }

    // Real and effective apart: access asks the real (1000), AT_EACCESS
    // the effective (root, its capabilities kept with the saved root id).
    child = fork();
    if (child == 0) {
        if (setresuid(1000, 0, 0)) _exit(2);
        failed = 0;
        want("real 1000, write root 644", access(at("root644"), W_OK), EACCES);
        // faccessat2 itself: bionic's faccessat takes no flags.
        want("effective root, write root 644", syscall(SYS_faccessat2, AT_FDCWD, at("root644"), W_OK, AT_EACCESS), 0);
        fflush(stdout);
        _exit(failed);
    }
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) {
        printf("access: the real-and-effective child (status %#x)\n", st);
        failed = 1;
    }

    // A read-only filesystem: no write, even for root; execute and read
    // as before.
    if (mount(NULL, base, NULL, MS_REMOUNT | MS_RDONLY, NULL)) {
        printf("access: remount (errno %d)\n", errno);
        return 1;
    }
    want("root, write on a read-only filesystem", access(at("root644"), W_OK), EROFS);
    want("root, read on a read-only filesystem", access(at("root644"), R_OK), 0);
    umount2(base, MNT_DETACH);
    rmdir(base);
    if (failed) return 1;
    printf("access ok\n");
    return 0;
}
