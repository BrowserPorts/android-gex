// binderfs, the filesystem the binder devices live in: mounted, looked at,
// given devices and relieved of them.
//
// - A mount is of type BINDERFS_SUPER_MAGIC. It has binder-control and a
//   features directory whose files read "1", and the devices the kernel is
//   configured to start every mount with: none, or binder, hwbinder and
//   vndbinder (Android's).
// - BINDER_CTL_ADD on binder-control makes a device and says its numbers:
//   a character device, 0600, its inode three more than its minor. A name
//   that is there is EEXIST, and a mount holds no more than its max=.
// - Each device has a context manager of its own, and one only.
// - A device can be given another mode, renamed and removed; one that is
//   open goes on working when its name is gone, and counts against max=
//   until it is closed. binder-control can be neither renamed nor removed,
//   and nothing else can be made here.
// - An option the filesystem does not have, or a max= past its limit, is
//   EINVAL.
//
// Needs the right to mount (root) and the filesystem; without them the
// program says so and exits 77.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

// include/uapi/linux/android/binderfs.h
struct binderfs_device {
    char name[256];
    uint32_t major, minor;
};
#define CTL_ADD _IOWR('b', 1, struct binderfs_device)
#define BINDERFS_MAGIC 0x6c6f6f70

static char dir[64];

static void die(const char *what, long a, long b) {
    printf("binderfs: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    // Whatever is still open in it.
    umount2(dir, MNT_DETACH);
    rmdir(dir);
    exit(1);
}

static const char *in(const char *name) {
    static char path[4][128];
    static int at;
    char *p = path[at++ & 3];
    snprintf(p, 128, "%s/%s", dir, name);
    return p;
}

static int add(int ctl, const char *name, struct binderfs_device *out) {
    struct binderfs_device d = {0};
    strncpy(d.name, name, sizeof d.name - 1);
    int r = ioctl(ctl, CTL_ADD, &d) ? -errno : 0;
    if (out) *out = d;
    return r;
}

int main(void) {
    snprintf(dir, sizeof dir, "/tmp/binderfs-test-%d", getpid());
    if (mkdir(dir, 0755)) {
        printf("binderfs: mkdir %s: errno %d\n", dir, errno);
        return 1;
    }
    if (mount("binder", dir, "binder", 0, "max=5")) {
        printf("binderfs: cannot mount one: errno %d\n", errno);
        rmdir(dir);
        return errno == EPERM || errno == ENODEV || errno == EACCES ? 77 : 1;
    }
    struct statfs fs;
    if (statfs(dir, &fs) || fs.f_type != BINDERFS_MAGIC) die("the mount's type", fs.f_type, 0);

    // What a mount starts with.
    int control = 0, features = 0, devices = 0, known = 0;
    DIR *d = opendir(dir);
    if (!d) die("opendir", 0, 0);
    for (struct dirent *e; (e = readdir(d));) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!strcmp(e->d_name, "binder-control")) {
            control += e->d_type == DT_CHR;
        } else if (!strcmp(e->d_name, "features")) {
            features += e->d_type == DT_DIR;
        } else if (!strcmp(e->d_name, "binder_logs")) {
            // The driver's state as text: only with stats=global.
            die("binder_logs in a mount that did not ask for it", 0, 0);
        } else {
            devices += e->d_type == DT_CHR;
            known += !strcmp(e->d_name, "binder") || !strcmp(e->d_name, "hwbinder") || !strcmp(e->d_name, "vndbinder");
        }
    }
    closedir(d);
    if (control != 1 || features != 1) die("binder-control and features", control, features);
    if (devices != known || (devices != 0 && devices != 3)) die("the devices a mount starts with", devices, known);

    struct stat st;
    if (stat(in("binder-control"), &st) || !S_ISCHR(st.st_mode) || (st.st_mode & 07777) != 0600) die("binder-control's node", st.st_mode, 0);
    if (stat(in("features"), &st) || !S_ISDIR(st.st_mode)) die("features", st.st_mode, 0);
    const char *feature[] = {"features/oneway_spam_detection", "features/extended_error"};
    for (int i = 0; i < 2; i++) {
        char text[8];
        int f = open(in(feature[i]), O_RDONLY | O_CLOEXEC);
        if (f < 0) die(feature[i], 0, 0);
        if (fstat(f, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 07777) != 0444) die("a feature's file", st.st_mode, 0);
        if (read(f, text, sizeof text) != 2 || memcmp(text, "1\n", 2)) die("a feature's text", text[0], 0);
        close(f);
    }

    // A device, by binder-control.
    int ctl = open(in("binder-control"), O_RDONLY | O_CLOEXEC);
    if (ctl < 0) die("open binder-control", 0, 0);
    struct binderfs_device made;
    if (add(ctl, "one", &made)) die("add a device", 0, 0);
    if (stat(in("one"), &st) || !S_ISCHR(st.st_mode) || (st.st_mode & 07777) != 0600) die("the device's node", st.st_mode, 0);
    if (major(st.st_rdev) != made.major || minor(st.st_rdev) != made.minor) die("the device's numbers", major(st.st_rdev), minor(st.st_rdev));
    if (st.st_ino != made.minor + 3) die("the device's inode", st.st_ino, made.minor);
    int r = add(ctl, "one", NULL);
    if (r != -EEXIST) die("add a name that is there", r, 0);
    r = add(ctl, "", NULL);
    if (r != -EACCES) die("add no name", r, 0);
    r = add(ctl, "a/b", NULL);
    if (r != -EACCES) die("add a name with a slash", r, 0);
    if (ioctl(ctl, BINDER_VERSION, &made) != -1 || errno != EINVAL) die("another ioctl of binder-control", errno, 0);
    // No more than max=.
    if (add(ctl, "two", NULL)) die("add a second device", 0, 0);
    int total = devices + 2;
    for (char name[8] = "more0"; total < 5; total++, name[4]++) {
        if (add(ctl, name, NULL)) die("add up to the mount's max", total, 0);
    }
    r = add(ctl, "toomany", NULL);
    if (r != -ENOSPC) die("add past the mount's max", r, 0);

    // Each device is its own: a context manager each, and one only.
    int one = open(in("one"), O_RDWR | O_CLOEXEC), again = open(in("one"), O_RDWR | O_CLOEXEC), two = open(in("two"), O_RDWR | O_CLOEXEC);
    if (one < 0 || again < 0 || two < 0) die("open the devices", one, two);
    struct binder_version v = {0};
    if (ioctl(one, BINDER_VERSION, &v) || v.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION) die("version", v.protocol_version, 0);
    uint32_t zero = 0;
    if (ioctl(one, BINDER_SET_CONTEXT_MGR, &zero)) die("context manager of one", 0, 0);
    if (ioctl(two, BINDER_SET_CONTEXT_MGR, &zero)) die("context manager of two", 0, 0);
    if (ioctl(again, BINDER_SET_CONTEXT_MGR, &zero) != -1 || errno != EBUSY) die("a second context manager of one", errno, 0);
    close(again);

    // Another mode, another name, no name.
    if (chmod(in("one"), 0666) || stat(in("one"), &st) || (st.st_mode & 07777) != 0666) die("chmod", st.st_mode, 0);
    if (fstat(one, &st) || (st.st_mode & 07777) != 0666 || !S_ISCHR(st.st_mode)) die("the open device's mode", st.st_mode, 0);
    if (rename(in("two"), in("three")) || stat(in("three"), &st) || stat(in("two"), &st) != -1) die("rename", 0, 0);
    if (unlink(in("one")) || stat(in("one"), &st) != -1 || errno != ENOENT) die("unlink", 0, 0);
    // A removed device that is still open works, and still counts.
    if (ioctl(one, BINDER_VERSION, &v)) die("the removed device, still open", 0, 0);
    r = add(ctl, "four", NULL);
    if (r != -ENOSPC) die("add where one was removed and is still open", r, 0);
    close(one);
    if (add(ctl, "four", NULL)) die("add where one was removed", 0, 0);
    if (unlink(in("binder-control")) != -1 || errno != EPERM) die("unlink binder-control", errno, 0);
    if (rename(in("binder-control"), in("other")) != -1 || errno != EPERM) die("rename binder-control", errno, 0);
    if (rename(in("three"), in("binder-control")) != -1 || errno != EPERM) die("rename over binder-control", errno, 0);
    if (mkdir(in("sub"), 0755) != -1 || errno != EPERM) die("mkdir", errno, 0);
    if (open(in("file"), O_CREAT | O_WRONLY, 0644) != -1 || errno != EACCES) die("create a file", errno, 0);
    close(two);
    close(ctl);

    // Options.
    char second[80];
    snprintf(second, sizeof second, "%s-2", dir);
    if (mkdir(second, 0755)) die("mkdir", 0, 0);
    if (mount("binder", second, "binder", 0, "nosuch=1") != -1 || errno != EINVAL) die("an option it does not have", errno, 0);
    if (mount("binder", second, "binder", 0, "max=1048577") != -1 || errno != EINVAL) die("a max past the limit", errno, 0);
    rmdir(second);

    if (umount(dir)) die("umount", 0, 0);
    if (rmdir(dir)) die("rmdir", 0, 0);
    printf("binderfs ok\n");
    return 0;
}
