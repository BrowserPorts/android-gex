// umount2's checks, in Linux's order (ksys_umount, can_umount,
// do_umount): flags it does not know, the path (its last link not
// followed for UMOUNT_NOFOLLOW), CAP_SYS_ADMIN, a mount there, then
// MNT_EXPIRE with MNT_FORCE or MNT_DETACH. And mount's CAP_SYS_ADMIN,
// asked after the target is found. Run as root.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW 8
#endif

static int failed;

static void want(const char *what, int r, int err) {
    int got = r == 0 ? 0 : errno;
    if (got != err) {
        printf("umount: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

int main(void) {
    char base[] = "/tmp/umount-XXXXXX";
    char dir[64], link[64], missing[64], plain[64];
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("umount: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(dir, sizeof dir, "%s/dir", base);
    snprintf(link, sizeof link, "%s/link", base);
    snprintf(missing, sizeof missing, "%s/missing", base);
    snprintf(plain, sizeof plain, "%s/plain", base);
    if (mkdir(dir, 0755) || mkdir(plain, 0755) || symlink(dir, link) || mount("tmpfs", dir, "tmpfs", 0, NULL)) {
        printf("umount: setup (errno %d)\n", errno);
        return 1;
    }
    want("a flag it does not know", umount2(dir, 0x10), EINVAL);
    want("a flag it does not know, on a path not there", umount2(missing, 0x10), EINVAL);
    want("a path not there", umount2(missing, 0), ENOENT);
    want("a directory nothing is mounted on", umount2(plain, 0), EINVAL);
    want("MNT_EXPIRE with MNT_DETACH", umount2(dir, MNT_EXPIRE | MNT_DETACH), EINVAL);
    want("MNT_EXPIRE with MNT_FORCE", umount2(dir, MNT_EXPIRE | MNT_FORCE), EINVAL);
    want("a link to a mount, not followed", umount2(link, UMOUNT_NOFOLLOW), EINVAL);

    pid_t child = fork();
    if (child == 0) {
        // No capabilities left: the ids all 1000.
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) _exit(2);
        failed = 0;
        want("unprivileged: a path not there", umount2(missing, 0), ENOENT);
        want("unprivileged: a flag it does not know", umount2(dir, 0x10), EINVAL);
        want("unprivileged", umount2(dir, 0), EPERM);
        want("unprivileged: a directory nothing is mounted on", umount2(plain, 0), EPERM);
        want("unprivileged: mount", mount("tmpfs", plain, "tmpfs", 0, NULL), EPERM);
        want("unprivileged: mount on a path not there", mount("tmpfs", missing, "tmpfs", 0, NULL), ENOENT);
        _exit(failed);
    }
    int st;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) {
        printf("umount: the unprivileged child (status %#x)\n", st);
        failed = 1;
    }

    want("a link to a mount, followed", umount2(link, 0), 0);
    want("again", umount2(dir, 0), EINVAL);
    umount2(base, MNT_DETACH);
    rmdir(base);
    if (failed) return 1;
    printf("umount ok\n");
    return 0;
}
