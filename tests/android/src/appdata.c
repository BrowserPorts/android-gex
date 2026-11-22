// What Android's zygote does for each app it starts (isolateAppData): in
// the child's own mount namespace, a tmpfs over each data directory
// (data, user, user_de), so the app sees none of the others' data; then
// user/0 made again as a link to data, in the new tmpfs, where it is not.
// The directories here are a tmpfs's of the test's own, made as an
// Android /data has them (user/0 a link to data). Run as root.
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

int main(void) {
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("appdata: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(p[0], sizeof p[0], "%s/data", base);
    snprintf(p[1], sizeof p[1], "%s/user", base);
    snprintf(p[2], sizeof p[2], "%s/user_de", base);
    snprintf(p[3], sizeof p[3], "%s/user/0", base);
    if (mkdir(p[0], 0771) || mkdir(p[1], 0711) || mkdir(p[2], 0711) || symlink(p[0], p[3])) {
        printf("appdata: setup (errno %d)\n", errno);
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL)) {
            printf("appdata: unshare (errno %d)\n", errno);
            _exit(1);
        }
        for (int i = 0; i < 3; i++) {
            if (mount("tmpfs", p[i], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "uid=0,gid=0,mode=0751")) {
                printf("appdata: mount over %s (errno %d)\n", p[i], errno);
                _exit(1);
            }
        }
        struct stat st;
        if (lstat(p[3], &st) == 0) {
            printf("appdata: user/0 is still there under the new tmpfs\n");
            _exit(1);
        }
        if (symlink(p[0], p[3])) {
            printf("appdata: making user/0 again (errno %d)\n", errno);
            _exit(1);
        }
        if (lstat(p[3], &st) || !S_ISLNK(st.st_mode)) {
            printf("appdata: user/0 is not a link (errno %d)\n", errno);
            _exit(1);
        }
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    // The parent's namespace is as it was: user/0 its own link.
    struct stat st;
    if (lstat(p[3], &st) || !S_ISLNK(st.st_mode)) {
        printf("appdata: the parent's user/0 changed (errno %d)\n", errno);
        return 1;
    }
    umount2(base, MNT_DETACH);
    rmdir(base);
    printf("appdata ok\n");
    return 0;
}
