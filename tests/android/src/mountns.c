// Whose mounts a process sees: the mount table is its mount namespace's,
// shared with every process in it.
//
// - What a child mounts, its parent sees, and what the parent mounts, a
//   child that was already running sees: one table, not a copy a process.
// - A process that asks for a namespace of its own (unshare(CLONE_NEWNS))
//   has the mounts there were, and what it mounts under a private mount
//   after that nobody else sees.
//
// Everything is done in a namespace of the program's own with nothing
// spreading out of it (every mount made private first), in a tmpfs it
// mounts for the purpose, so the machine it runs on is left as it was.
//
// Needs the right to mount (root); without it the program says so and
// exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char dir[64];

static void die(const char *what, long a, long b) {
    printf("mountns: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *in(const char *name) {
    static char path[4][160];
    static int at;
    char *p = path[at++ & 3];
    snprintf(p, 160, "%s/%s", dir, name);
    return p;
}

static void touch(const char *name) {
    int fd = open(in(name), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0) die(name, 0, 0);
    close(fd);
}

static int there(const char *name) {
    return access(in(name), F_OK) == 0;
}

static void wait_ok(pid_t pid, const char *what) {
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) die(what, st, 0);
}

int main(void) {
    if (geteuid() != 0) {
        printf("mountns: not root, cannot mount\n");
        return 77;
    }
    // A namespace of the program's own, with nothing spreading out of it.
    if (unshare(CLONE_NEWNS)) {
        printf("mountns: cannot leave the mount namespace: errno %d\n", errno);
        return errno == EPERM || errno == EINVAL ? 77 : 1;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) die("making every mount private", 0, 0);
    snprintf(dir, sizeof dir, "/tmp/mountns-test-%d", getpid());
    if (mkdir(dir, 0755)) die("mkdir", 0, 0);
    if (mount("tmpfs", dir, "tmpfs", 0, NULL)) die("mount", 0, 0);
    if (mkdir(in("a"), 0755) || mkdir(in("b"), 0755) || mkdir(in("p"), 0755)) die("mkdir", 0, 0);

    // A change of how a mount spreads is of something mounted.
    if (mount(NULL, in("a"), NULL, MS_PRIVATE, NULL) != -1 || errno != EINVAL) die("propagation of what is not a mount", errno, EINVAL);

    // What a child mounts, the parent sees.
    pid_t pid = fork();
    if (pid < 0) die("fork", 0, 0);
    if (pid == 0) {
        if (mount("tmpfs", in("a"), "tmpfs", 0, NULL)) die("the child's mount", 0, 0);
        touch("a/made");
        _exit(0);
    }
    wait_ok(pid, "the child that mounts");
    if (!there("a/made")) die("the child's mount, as the parent sees it", 0, 0);

    // What the parent mounts, a child that was already running sees.
    int go[2], looked[2];
    char c;
    if (pipe(go) || pipe(looked)) die("pipe", 0, 0);
    pid = fork();
    if (pid < 0) die("fork", 0, 0);
    if (pid == 0) {
        close(go[1]);
        if (there("b/made")) die("a mount not made yet", 0, 0);
        if (write(looked[1], "l", 1) != 1 || read(go[0], &c, 1) != 1) die("the child's wait", 0, 0);
        _exit(there("b/made") ? 0 : 2);
    }
    close(go[0]);
    // Not until the child has looked, and found nothing.
    if (read(looked[0], &c, 1) != 1) die("the child's look", 0, 0);
    if (mount("tmpfs", in("b"), "tmpfs", 0, NULL)) die("the parent's mount", 0, 0);
    touch("b/made");
    if (write(go[1], "g", 1) != 1) die("the parent's word", 0, 0);
    close(go[1]);
    wait_ok(pid, "the child that was running when the parent mounted");

    // A namespace of its own: the mounts there were, and its own after.
    pid = fork();
    if (pid < 0) die("fork", 0, 0);
    if (pid == 0) {
        if (unshare(CLONE_NEWNS)) die("the child's unshare", 0, 0);
        if (!there("a/made") || !there("b/made")) die("the mounts there were, in the new namespace", 0, 0);
        if (mount("tmpfs", in("p"), "tmpfs", 0, NULL)) die("the mount in the new namespace", 0, 0);
        touch("p/made");
        if (umount(in("a"))) die("the unmount in the new namespace", 0, 0);
        if (there("a/made")) die("what was unmounted", 0, 0);
        _exit(there("p/made") ? 0 : 2);
    }
    wait_ok(pid, "the child with a namespace of its own");
    if (there("p/made")) die("a mount of another namespace, seen from this one", 0, 0);
    if (!there("a/made")) die("a mount another namespace unmounted for itself", 0, 0);

    if (umount(in("a")) || umount(in("b")) || umount(dir)) die("umount", 0, 0);
    rmdir(dir);
    printf("mountns ok\n");
    return 0;
}
