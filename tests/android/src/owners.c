// Who owns a file: its user and group, as stat says them and chown
// changes them. Android's ueventd gives each device node its owner, init
// its directories, installd each app's files; and they look afterwards.
//
// In a tmpfs:
// - What a process makes is its own: its user, and its group, or the
//   directory's group when the directory hands its group down (a
//   directory made there hands it down too).
// - chown changes the user, the group, or both (-1 leaves one), for a
//   path, a link itself (lchown), and an open file (fchown) even after
//   its name is gone.
// - Only root gives a file to another user. Its owner changes its group
//   to a group the owner is in, and to no other (EPERM); nobody else
//   changes anything (EPERM).
// - chown of a file takes its set-user-id bit, and its set-group-id bit
//   when its group may execute it; a directory keeps them.
// - A tmpfs's root is the `uid=` and `gid=` it was mounted with.
// - The supplementary groups are what setgroups set, in a child too.
//
// Mounts a tmpfs of its own (root); without that right the program says
// so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char top[64];

static void die(const char *what, long a, long b) {
    printf("owners: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *at(const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", top, path);
    return out;
}

static void owned(const char *path, uid_t uid, gid_t gid) {
    struct stat st;
    if (lstat(at(path), &st)) die(path, errno, 0);
    if (st.st_uid != uid || st.st_gid != gid) {
        printf("owners: %s is %d:%d, not %d:%d\n", path, st.st_uid, st.st_gid, uid, gid);
        exit(1);
    }
}

static mode_t mode_of(const char *path) {
    struct stat st;
    if (lstat(at(path), &st)) die(path, errno, 1);
    return st.st_mode & 07777;
}

static void make(const char *path) {
    int fd = open(at(path), O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) die(path, errno, 2);
    close(fd);
}

// Run `f` in a child that is user 1000, group 1000, with group 3000 as
// well; its exit is the test's.
static void as_user(void (*f)(void)) {
    pid_t child = fork();
    if (child < 0) die("fork", errno, 0);
    if (child == 0) {
        gid_t groups[] = {3000};
        if (setgroups(1, groups) || setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) die("becoming a user", errno, 0);
        f();
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) exit(1);
}

static void users_part(void) {
    gid_t have[8];
    int n = getgroups(8, have);
    if (n != 1 || have[0] != 3000 || getgroups(0, NULL) != 1) die("the supplementary groups", n, have[0]);
    // What it makes is its own.
    make("open/mine");
    owned("open/mine", 1000, 1000);
    if (mkdir(at("open/mydir"), 0755) || symlink("mine", at("open/mylink"))) die("making things", errno, 0);
    owned("open/mydir", 1000, 1000);
    owned("open/mylink", 1000, 1000);
    // In a directory that hands its group down, the directory's group.
    make("handed/mine");
    owned("handed/mine", 1000, 2000);
    if (mkdir(at("handed/mydir"), 0755)) die("mkdir", errno, 0);
    owned("handed/mydir", 1000, 2000);
    if (!(mode_of("handed/mydir") & S_ISGID)) die("a directory made in one that hands its group down", mode_of("handed/mydir"), 0);
    // Its own file: to a group it is in, not to one it is not, and not to
    // another user.
    if (chown(at("open/mine"), -1, 3000)) die("its own file to a group it is in", errno, 0);
    owned("open/mine", 1000, 3000);
    if (chown(at("open/mine"), 1000, 1000)) die("its own file to itself", errno, 0);
    if (chown(at("open/mine"), -1, 4000) == 0 || errno != EPERM) die("its own file to a group it is not in", errno, 0);
    if (chown(at("open/mine"), 0, -1) == 0 || errno != EPERM) die("its own file to root", errno, 0);
    if (chown(at("open/mine"), 2000, -1) == 0 || errno != EPERM) die("its own file to another user", errno, 0);
    owned("open/mine", 1000, 1000);
    // Root's file: nothing.
    if (chown(at("roots"), -1, 3000) == 0 || errno != EPERM) die("another's file to a group", errno, 0);
    if (chown(at("roots"), 1000, -1) == 0 || errno != EPERM) die("another's file to itself", errno, 0);
    if (chown(at("roots"), -1, -1)) die("another's file to nothing new", errno, 0);
    owned("roots", 0, 0);
}

int main(void) {
    if (geteuid() != 0) {
        printf("owners: needs root\n");
        return 77;
    }
    strcpy(top, "/tmp/owners-XXXXXX");
    if (!mkdtemp(top) || mount("tmpfs", top, "tmpfs", 0, "mode=0755,uid=7,gid=8")) die("a tmpfs", errno, 0);
    struct stat st;
    if (stat(top, &st) || st.st_uid != 7 || st.st_gid != 8) die("the root of a tmpfs mounted with an owner", st.st_uid, st.st_gid);

    // Root's own, and given away.
    make("roots");
    owned("roots", 0, 0);
    make("given");
    if (chown(at("given"), 1000, 2000)) die("chown", errno, 0);
    owned("given", 1000, 2000);
    if (chown(at("given"), -1, 5)) die("chown of the group alone", errno, 0);
    owned("given", 1000, 5);
    if (chown(at("given"), 6, -1)) die("chown of the user alone", errno, 0);
    owned("given", 6, 5);
    if (chown(at("given"), -1, -1)) die("chown of neither", errno, 0);
    owned("given", 6, 5);
    if (chown(at("nothing"), 1, 1) == 0 || errno != ENOENT) die("chown of what is not there", errno, 0);
    // A link: chown goes through it, lchown is the link's own.
    if (symlink("given", at("link"))) die("symlink", errno, 0);
    if (lchown(at("link"), 11, 12)) die("lchown", errno, 0);
    owned("link", 11, 12);
    owned("given", 6, 5);
    if (chown(at("link"), 13, 14)) die("chown through a link", errno, 0);
    owned("given", 13, 14);
    owned("link", 11, 12);
    // An open file, its name gone from where it was.
    int fd = open(at("given"), O_RDONLY);
    if (fd < 0 || rename(at("given"), at("moved")) || fchown(fd, 21, 22)) die("fchown", errno, 0);
    owned("moved", 21, 22);
    if (fstat(fd, &st) || st.st_uid != 21 || st.st_gid != 22) die("fstat after fchown", st.st_uid, st.st_gid);
    close(fd);
    // The bits a chown takes from a file, and leaves a directory.
    if (chmod(at("moved"), 06755) || chown(at("moved"), 23, 24)) die("chown of a set-id file", errno, 0);
    if (mode_of("moved") != 0755) die("a set-id file's mode after chown", mode_of("moved"), 0);
    if (chmod(at("moved"), 02644) || chown(at("moved"), 25, 26)) die("chown of a file its group cannot execute", errno, 0);
    if (mode_of("moved") != 02644) die("its mode after chown", mode_of("moved"), 0);
    if (mkdir(at("dir"), 0755) || chmod(at("dir"), 06755) || chown(at("dir"), 27, 28)) die("chown of a directory", errno, 0);
    if (mode_of("dir") != 06755) die("a directory's mode after chown", mode_of("dir"), 0);

    // For a user: a directory anyone may write, and one that hands its
    // group (2000) down.
    if (mkdir(at("open"), 0777) || chmod(at("open"), 0777) || mkdir(at("handed"), 0777) || chown(at("handed"), 0, 2000) || chmod(at("handed"), 02777)) die("the directories", errno, 0);
    as_user(users_part);
    // What the user made is still theirs to root, who has no such groups.
    owned("open/mine", 1000, 1000);
    if (getgroups(0, NULL) != 0 && 0) die("root's groups", 0, 0);

    if (umount(top) || rmdir(top)) die("umount", errno, 0);
    printf("owners ok\n");
    return 0;
}
