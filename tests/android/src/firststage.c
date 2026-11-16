// What Android's first-stage init leaves for the stages after it, done by
// hand, and then `init` run in its place: for starting the image's init
// where there are no partitions for its own first stage to mount (the
// image is a directory tree already).
//
//   firststage [init's arguments...]     (default: selinux_setup)
//
// The mounts and nodes are first_stage_init.cpp's, in its order: a tmpfs
// on /dev with pts, socket and dm-user in it, sysfs on /sys (which
// ueventd makes /dev from: without it its cold boot finds no device),
// the kernel log, the random devices, ptmx and null by number, and tmpfs
// on /mnt, /debug_ramdisk and /second_stage_resources. Left out, and
// said: devpts on /dev/pts, where the kernel cannot mount one; proc and
// selinuxfs, which whoever runs this has mounted already.
//
// It must be the process that becomes init: what it mounts, init has.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define CHECK(x) \
    if ((x) != 0) { \
        printf("firststage: %s: errno %d\n", #x, errno); \
        return 1; \
    }

int main(int argc, char **argv) {
    CHECK(mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755"));
    CHECK(mkdir("/dev/pts", 0755));
    CHECK(mkdir("/dev/socket", 0755));
    CHECK(mkdir("/dev/dm-user", 0755));
    if (mount("devpts", "/dev/pts", "devpts", 0, NULL)) printf("firststage: no devpts on /dev/pts: errno %d\n", errno);
    CHECK(mount("sysfs", "/sys", "sysfs", 0, NULL));
    CHECK(mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11)));
    CHECK(mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8)));
    CHECK(mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)));
    CHECK(mknod("/dev/ptmx", S_IFCHR | 0666, makedev(5, 2)));
    CHECK(mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3)));
    // The device-mapper's node, which first-stage init makes for itself
    // before it looks at its partitions (InitDeviceMapper: the misc
    // device's uevent again, through the code ueventd makes nodes with,
    // with no rule yet to give it another owner or mode). Second-stage
    // init asks the device-mapper about system_ext and product before
    // ueventd has run.
    CHECK(mknod("/dev/device-mapper", S_IFCHR | 0600, makedev(10, 236)));
    CHECK(mount("tmpfs", "/mnt", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "mode=0755,uid=0,gid=1000"));
    CHECK(mkdir("/mnt/vendor", 0755));
    CHECK(mkdir("/mnt/product", 0755));
    CHECK(mount("tmpfs", "/debug_ramdisk", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "mode=0755,uid=0,gid=0"));
    CHECK(mount("tmpfs", "/second_stage_resources", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "mode=0755,uid=0,gid=0"));

    char *args[16] = {"/system/bin/init", "selinux_setup", NULL};
    for (int i = 1; i < argc && i < 14; i++) {
        args[i] = argv[i];
        args[i + 1] = NULL;
    }
    char *env[] = {"PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin", NULL};
    execve(args[0], args, env);
    printf("firststage: execve %s: errno %d\n", args[0], errno);
    return 1;
}
