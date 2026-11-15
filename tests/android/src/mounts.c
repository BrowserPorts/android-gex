// What a mount is made with, and what it says of itself afterwards:
// /proc/mounts and /proc/self/mountinfo name each mount's source and its
// options, which programs read (Android's apexd finds its mounted APEXes
// by them), and two of the flags change what the mount allows.
//
// - A tmpfs takes its options: `mode` is its root directory's (1777
//   without one); `size`, `uid`, `gid` are shown as it shows them; an
//   option it has not, or a mode that is not one, is EINVAL.
// - /proc/mounts: the source as it was written, the mount point (a space
//   in it as \040), the type, and the options in the kernel's order: ro
//   or rw, the mount's flags, then the filesystem's own.
// - /proc/self/mountinfo: the mount's options before the dash, the
//   filesystem's after it, with the type and the source between.
// - MS_RDONLY: nothing can be made or changed in it (EROFS).
// - MS_NODEV: a device node in it does not open (EACCES); in another
//   mount the same node does.
// - MS_REMOUNT gives the mount the flags of the remount: read-only and
//   back.
//
// The kernel this runs on may add `seclabel` (SELinux) and `inode64` (a
// kernel built to say so) to a tmpfs's options: they are taken out
// before comparing.
//
// Needs root; without it the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static char top[PATH_MAX];

static void die(const char *what, long a, long b) {
    printf("mounts: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *at(const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", top, path);
    return out;
}

// `options` without the two a kernel may add.
static void plain(char *options) {
    const char *extra[] = {",seclabel", ",inode64"};
    for (int i = 0; i < 2; i++) {
        char *p;
        while ((p = strstr(options, extra[i]))) memmove(p, p + strlen(extra[i]), strlen(p + strlen(extra[i])) + 1);
    }
}

// The line of /proc/mounts for mount point `point` (as the file writes
// it): its source, type and options.
static void in_mounts(const char *point, const char *source, const char *type, const char *options) {
    FILE *f = fopen("/proc/mounts", "re");
    if (!f) die("/proc/mounts", errno, 0);
    char line[1024], src[256], mnt[256], ty[64], opts[512];
    int found = 0, a, b;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%255s %255s %63s %511s %d %d", src, mnt, ty, opts, &a, &b) != 6 || strcmp(mnt, point)) continue;
        found++;
        plain(opts);
        if (strcmp(src, source) || strcmp(ty, type) || strcmp(opts, options) || a || b) {
            printf("mounts: /proc/mounts has '%s %s %s %s' for %s, not '%s %s %s'\n", src, mnt, ty, opts, point, source, type, options);
            exit(1);
        }
    }
    fclose(f);
    if (found != 1) die("lines in /proc/mounts for a mount", found, 0);
}

// The line of /proc/self/mountinfo for `point`: the mount's options, and
// after the dash the type, the source and the filesystem's options.
static void in_mountinfo(const char *point, const char *mount_options, const char *type, const char *source, const char *fs_options) {
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f) die("/proc/self/mountinfo", errno, 0);
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        char root[256], mnt[256], mopts[256], ty[64], src[256], fopts[512];
        int id, parent, major, minor;
        if (sscanf(line, "%d %d %d:%d %255s %255s %255s", &id, &parent, &major, &minor, root, mnt, mopts) != 7 || strcmp(mnt, point)) continue;
        char *dash = strstr(line, " - ");
        if (!dash || sscanf(dash + 3, "%63s %255s %511s", ty, src, fopts) != 3) die("a line of mountinfo", 0, 0);
        found++;
        plain(fopts);
        if (strcmp(root, "/") || strcmp(mopts, mount_options) || strcmp(ty, type) || strcmp(src, source) || strcmp(fopts, fs_options)) {
            printf("mounts: mountinfo has '%s %s - %s %s %s' for %s\n", root, mopts, ty, src, fopts, point);
            exit(1);
        }
    }
    fclose(f);
    if (found != 1) die("lines in mountinfo for a mount", found, 0);
}

static int make(const char *path) {
    int fd = open(at(path), O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}

int main(void) {
    if (geteuid() != 0) {
        printf("mounts: needs root\n");
        return 77;
    }
    // By its real name, which is the one the kernel lists it under (/tmp
    // may be a link).
    char made[64] = "/tmp/mounts-XXXXXX";
    if (!mkdtemp(made) || !realpath(made, top) || mount("tmpfs", top, "tmpfs", 0, NULL)) die("a tmpfs", errno, 0);
    struct stat st;
    // With no options: its root is 1777, and it says only how it is mounted.
    if (stat(top, &st) || (st.st_mode & 07777) != 01777) die("a tmpfs's root with no mode given", st.st_mode, 0);
    in_mounts(top, "tmpfs", "tmpfs", "rw,relatime");
    in_mountinfo(top, "rw,relatime", "tmpfs", "tmpfs", "rw");

    // With options and flags.
    if (mkdir(at("opts"), 0755) || mkdir(at("ro"), 0755) || mkdir(at("no dev"), 0755) || mkdir(at("times"), 0755)) die("mkdir", errno, 0);
    if (mount("a-source", at("opts"), "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0750,uid=7,gid=8,size=1m")) die("mount with options", errno, 0);
    if (stat(at("opts"), &st) || (st.st_mode & 07777) != 0750) die("a tmpfs's root with a mode", st.st_mode, 0);
    in_mounts(at("opts"), "a-source", "tmpfs", "rw,nosuid,noexec,relatime,size=1024k,mode=750,uid=7,gid=8");
    in_mountinfo(at("opts"), "rw,nosuid,noexec,relatime", "tmpfs", "a-source", "rw,size=1024k,mode=750,uid=7,gid=8");
    if (make("opts/file")) die("a file in it", errno, 0);
    if (mount("tmpfs", at("times"), "tmpfs", 0, "mode=0755,nonsense=1") == 0 || errno != EINVAL) die("an option a tmpfs has not", errno, 0);
    if (mount("tmpfs", at("times"), "tmpfs", 0, "mode=rwx") == 0 || errno != EINVAL) die("a mode that is not one", errno, 0);
    if (mount("none", at("times"), "tmpfs", MS_NOATIME | MS_NODIRATIME, "mode=755")) die("mount noatime", errno, 0);
    in_mounts(at("times"), "none", "tmpfs", "rw,noatime,nodiratime,mode=755");
    if (mount(NULL, at("times"), NULL, MS_REMOUNT | MS_STRICTATIME, NULL)) die("remount strictatime", errno, 0);
    in_mounts(at("times"), "none", "tmpfs", "rw,mode=755");

    // Read-only.
    if (mount("tmpfs", at("ro"), "tmpfs", 0, "mode=755") || make("ro/before") || mkdir(at("ro/dir"), 0755)) die("a mount to make read-only", errno, 0);
    if (mount(NULL, at("ro"), NULL, MS_REMOUNT | MS_RDONLY | MS_NODEV, NULL)) die("remount read-only", errno, 0);
    in_mounts(at("ro"), "tmpfs", "tmpfs", "ro,nodev,relatime,mode=755");
    in_mountinfo(at("ro"), "ro,nodev,relatime", "tmpfs", "tmpfs", "ro,mode=755");
    if (make("ro/new") != EROFS) die("a file made in a read-only mount", errno, 0);
    if (open(at("ro/before"), O_WRONLY) >= 0 || errno != EROFS) die("a file opened for writing there", errno, 0);
    int fd = open(at("ro/before"), O_RDONLY);
    if (fd < 0) die("a file opened for reading there", errno, 0);
    close(fd);
    if (mkdir(at("ro/new"), 0755) == 0 || errno != EROFS) die("mkdir there", errno, 0);
    if (mkdir(at("ro/dir"), 0755) == 0 || errno != EEXIST) die("mkdir of what is there", errno, 0);
    if (unlink(at("ro/before")) == 0 || errno != EROFS) die("unlink there", errno, 0);
    if (rmdir(at("ro/dir")) == 0 || errno != EROFS) die("rmdir there", errno, 0);
    if (rename(at("ro/before"), at("ro/after")) == 0 || errno != EROFS) die("rename there", errno, 0);
    if (chmod(at("ro/before"), 0600) == 0 || errno != EROFS) die("chmod there", errno, 0);
    if (symlink("before", at("ro/link")) == 0 || errno != EROFS) die("symlink there", errno, 0);
    if (access(at("ro/before"), W_OK) == 0 || errno != EROFS) die("access for writing there", errno, 0);
    if (access(at("ro/before"), R_OK)) die("access for reading there", errno, 0);
    // And back.
    if (mount(NULL, at("ro"), NULL, MS_REMOUNT, NULL)) die("remount for writing", errno, 0);
    in_mounts(at("ro"), "tmpfs", "tmpfs", "rw,relatime,mode=755");
    if (make("ro/new") || unlink(at("ro/before"))) die("a mount made writable again", errno, 0);

    // nodev: a node is made there, and does not open; the same number in
    // a mount without the flag does. The mount point has a space in it.
    if (mount("tmpfs", at("no dev"), "tmpfs", MS_NODEV, "mode=755")) die("mount nodev", errno, 0);
    char escaped[128];
    snprintf(escaped, sizeof escaped, "%s/no\\040dev", top);
    in_mounts(escaped, "tmpfs", "tmpfs", "rw,nodev,relatime,mode=755");
    if (mknod(at("no dev/null"), S_IFCHR | 0666, makedev(1, 3)) || mknod(at("opts/null"), S_IFCHR | 0666, makedev(1, 3))) die("mknod", errno, 0);
    if (open(at("no dev/null"), O_RDONLY) >= 0 || errno != EACCES) die("a device node in a nodev mount", errno, 0);
    if (stat(at("no dev/null"), &st) || !S_ISCHR(st.st_mode)) die("stat of it", errno, 0);
    fd = open(at("opts/null"), O_RDWR);
    if (fd < 0) die("a device node in a mount without nodev", errno, 0);
    close(fd);

    if (umount(at("no dev")) || umount(at("ro")) || umount(at("times")) || umount(at("opts")) || umount(top) || rmdir(top)) die("umount", errno, 0);
    printf("mounts ok\n");
    return 0;
}
