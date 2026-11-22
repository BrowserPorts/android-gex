// What Android's zygote does for each app it starts (isolateAppData): in
// the child's own mount namespace, a tmpfs over each data directory
// (data, user, user_de), so the app sees none of the others' data; then
// user/0 made again as a link to data, in the new tmpfs, where it is not.
// The directories here are a tmpfs's of the test's own, made as an
// Android /data has them (data bound onto user/0, as init.rc says) and
// shared, as init leaves its tree; a zygote's namespace a slave of it,
// and two apps in turn, each in a copy of the zygote's. A mount covers
// what is mounted where it is and under it: the bind on user/0 is not
// seen under the app's tmpfs on user. Run as root.
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char base[] = "/tmp/appdata-XXXXXX";
static char p[4][128];

// An app: as isolateAppData does it, in a namespace copied from the
// zygote's with nothing more done to it (its mounts are slaves already).
static int isolate(void) {
    if (unshare(CLONE_NEWNS)) {
        printf("appdata: unshare (errno %d)\n", errno);
        return 1;
    }
    for (int i = 0; i < 3; i++) {
        if (mount("tmpfs", p[i], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "uid=0,gid=0,mode=0751")) {
            printf("appdata: mount over %s (errno %d)\n", p[i], errno);
            return 1;
        }
    }
    struct stat st;
    if (lstat(p[3], &st) == 0) {
        printf("appdata: user/0 is still there under the new tmpfs\n");
        return 1;
    }
    if (symlink(p[0], p[3])) {
        printf("appdata: making user/0 again (errno %d)\n", errno);
        return 1;
    }
    if (lstat(p[3], &st) || !S_ISLNK(st.st_mode)) {
        printf("appdata: user/0 is not a link (errno %d)\n", errno);
        return 1;
    }
    return 0;
}

int main(void) {
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("appdata: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(p[0], sizeof p[0], "%s/data", base);
    snprintf(p[1], sizeof p[1], "%s/user", base);
    snprintf(p[2], sizeof p[2], "%s/user_de", base);
    snprintf(p[3], sizeof p[3], "%s/user/0", base);
    if (mkdir(p[0], 0771) || mkdir(p[1], 0711) || mkdir(p[2], 0711) || mkdir(p[3], 0700) ||
        mount(p[0], p[3], NULL, MS_BIND, NULL)) {
        printf("appdata: setup (errno %d)\n", errno);
        return 1;
    }
    struct stat data, st;
    if (stat(p[0], &data)) return 1;
#define IS_DATA(path) (stat(path, &st) == 0 && st.st_dev == data.st_dev && st.st_ino == data.st_ino)
    // Two tmpfs mounts on user, over the bind on user/0: the later is the
    // one seen, and each unmount shows what was below it again.
    if (mount("tmpfs", p[1], "tmpfs", 0, NULL)) {
        printf("appdata: stacking (errno %d)\n", errno);
        return 1;
    }
    if (lstat(p[3], &st) == 0) {
        printf("appdata: the bind on user/0 shows through a tmpfs on user\n");
        return 1;
    }
    if (mkdir(p[3], 0700) || mount("tmpfs", p[1], "tmpfs", 0, NULL)) {
        printf("appdata: stacking (errno %d)\n", errno);
        return 1;
    }
    if (lstat(p[3], &st) == 0) {
        printf("appdata: a stacked tmpfs shows the one below it\n");
        return 1;
    }
    if (umount2(p[1], 0) || lstat(p[3], &st) || !S_ISDIR(st.st_mode) || IS_DATA(p[3])) {
        printf("appdata: the first tmpfs again (errno %d)\n", errno);
        return 1;
    }
    if (umount2(p[1], 0) || !IS_DATA(p[3])) {
        printf("appdata: the bind on user/0 again (errno %d)\n", errno);
        return 1;
    }
    // A mount with another under it is busy, but for MNT_DETACH.
    char de0[160];
    snprintf(de0, sizeof de0, "%s/0", p[2]);
    if (mount("tmpfs", p[2], "tmpfs", 0, NULL) || mkdir(de0, 0700) || mount("tmpfs", de0, "tmpfs", 0, NULL)) {
        printf("appdata: user_de (errno %d)\n", errno);
        return 1;
    }
    if (umount2(p[2], 0) != -1 || errno != EBUSY) {
        printf("appdata: an unmount with a mount under it (errno %d)\n", errno);
        return 1;
    }
    if (umount2(p[2], MNT_DETACH) || lstat(de0, &st) == 0) {
        printf("appdata: a detached unmount (errno %d)\n", errno);
        return 1;
    }
    // Shared, as init leaves the whole tree.
    if (mount(NULL, base, NULL, MS_SHARED, NULL)) {
        printf("appdata: shared (errno %d)\n", errno);
        return 1;
    }
    pid_t zygote = fork();
    if (zygote == 0) {
        // The zygote: a namespace of its own, a slave of the first.
        if (unshare(CLONE_NEWNS) || mount("rootfs", "/", NULL, MS_REC | MS_SLAVE, NULL)) {
            printf("appdata: the zygote's namespace (errno %d)\n", errno);
            _exit(1);
        }
        for (int app = 0; app < 2; app++) {
            pid_t child = fork();
            if (child == 0) _exit(isolate());
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
                printf("appdata: app %d failed\n", app);
                _exit(1);
            }
            // What an app mounted in its own namespace is its alone.
            struct stat st;
            if (!IS_DATA(p[3])) {
                printf("appdata: the zygote's user/0 changed after app %d (errno %d)\n", app, errno);
                _exit(1);
            }
        }
        _exit(0);
    }
    int status;
    if (waitpid(zygote, &status, 0) != zygote || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    // The first namespace is as it was: data bound on user/0.
    if (!IS_DATA(p[3])) {
        printf("appdata: the parent's user/0 changed (errno %d)\n", errno);
        return 1;
    }
    umount2(base, MNT_DETACH);
    rmdir(base);
    printf("appdata ok\n");
    return 0;
}
