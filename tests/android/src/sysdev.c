// sysfs's devices, and the events they send: how Android's ueventd (and
// udev) learns what devices there are and makes /dev.
//
// - /dev/null's device is at devices/virtual/mem/null: `dev` reads its
//   number, `uevent` its variables, `subsystem` leads to its class; and
//   class/mem/null and dev/char/1:3 lead to it. So for the other memory
//   devices and the terminals.
// - A write of an action to a `uevent` file has the kernel broadcast the
//   device's event on the uevent socket: the action and path, ACTION,
//   DEVPATH, SUBSYSTEM, SYNTH_UUID (0, or the one the write gave, with a
//   SYNTH_ARG_ for each KEY=VALUE after it), the device's variables, and
//   the event's number, which kernel/uevent_seqnum then reads. It is the
//   kernel's: from port 0 to group 1, as root's, by no process.
// - Anything that is not an action is EINVAL, and nothing is sent.
// - Nothing can be made in it: a directory is EPERM, a file EACCES.
// - A node made with the number and mode an event gives is the device:
//   what ueventd does with it.
//
// Mounts a sysfs of its own (root); without that right the program says
// so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

static char sys[64];

static void die(const char *what, long a, long b) {
    printf("sysdev: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *at(const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", sys, path);
    return out;
}

static void reads(const char *path, const char *want) {
    char text[256] = {0};
    int fd = open(at(path), O_RDONLY);
    if (fd < 0) die(path, fd, 0);
    ssize_t n = read(fd, text, sizeof text - 1);
    close(fd);
    if (n < 0 || strcmp(text, want)) {
        printf("sysdev: %s reads '%s'\n", path, text);
        exit(1);
    }
}

static void leads(const char *path, const char *want) {
    char target[256] = {0};
    if (readlink(at(path), target, sizeof target - 1) < 0 || strcmp(target, want)) {
        printf("sysdev: %s leads to '%s' (errno %d)\n", path, target, errno);
        exit(1);
    }
}

// Write `action` to a device's uevent file: 0, or the errno.
static int act(const char *path, const char *action) {
    int fd = open(at(path), O_WRONLY);
    if (fd < 0) die(path, fd, 0);
    ssize_t n = write(fd, action, strlen(action));
    int e = n < 0 ? errno : 0;
    if (n >= 0 && (size_t)n != strlen(action)) die("a short write of an action", n, 0);
    close(fd);
    return e;
}

// The next event about `devpath` on the socket, as fields separated by
// '|' where the datagram has NULs, with where it came from checked.
// Other devices' events on a real kernel are passed over.
static const char *event(int s, const char *devpath) {
    static char text[4096];
    for (int tries = 0; tries < 100; tries++) {
        struct pollfd p = {s, POLLIN, 0};
        if (poll(&p, 1, 100) < 0) die("poll", 0, 0);
        if (!(p.revents & POLLIN)) continue;
        struct sockaddr_nl from;
        char control[CMSG_SPACE(sizeof(struct ucred))];
        struct iovec iov = {text, sizeof text - 1};
        struct msghdr m = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control};
        ssize_t n = recvmsg(s, &m, 0);
        if (n < 0) die("recvmsg", errno, 0);
        text[n] = 0;
        char *mark = strchr(text, '@');
        if (!mark || strcmp(mark + 1, devpath)) continue;
        if (from.nl_pid != 0 || from.nl_groups != 1) die("an event's sender", from.nl_pid, from.nl_groups);
        struct ucred cred = {-1, -1, -1};
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS) memcpy(&cred, CMSG_DATA(c), sizeof cred);
        }
        if (cred.pid != 0 || cred.uid != 0 || cred.gid != 0) die("an event's credentials", cred.pid, cred.uid);
        if (text[n - 1] != 0) die("an event's last byte", text[n - 1], n);
        for (ssize_t i = 0; i < n - 1; i++) {
            if (!text[i]) text[i] = '|';
        }
        return text;
    }
    return NULL;
}

// An event with its number taken off the end: the number.
static unsigned long long numbered(char *text) {
    char *seq = strstr(text, "|SEQNUM=");
    if (!seq) die("an event with no number", 0, 0);
    unsigned long long n = strtoull(seq + 8, NULL, 10);
    *seq = 0;
    return n;
}

static unsigned long long seqnum(void) {
    char text[32] = {0};
    int fd = open(at("kernel/uevent_seqnum"), O_RDONLY);
    if (fd < 0 || read(fd, text, sizeof text - 1) <= 0) die("kernel/uevent_seqnum", fd, 0);
    close(fd);
    return strtoull(text, NULL, 10);
}

static void expect(int s, const char *file, const char *action, const char *devpath, const char *want) {
    unsigned long long before = seqnum();
    if (act(file, action)) die(file, errno, 0);
    const char *got = event(s, devpath);
    if (!got) die("no event came", 0, 0);
    char text[4096];
    strcpy(text, got);
    unsigned long long n = numbered(text);
    if (strcmp(text, want)) {
        printf("sysdev: '%s' to %s sent '%s'\n", action, file, text);
        exit(1);
    }
    if (n <= before || seqnum() < n) die("an event's number", n, before);
}

int main(void) {
    if (geteuid() != 0) {
        printf("sysdev: needs root\n");
        return 77;
    }
    strcpy(sys, "/tmp/sysdev-XXXXXX");
    if (!mkdtemp(sys)) die("mkdtemp", errno, 0);
    if (mount("sysfs", sys, "sysfs", 0, NULL)) die("mount of sysfs", errno, 0);
    struct statfs sf;
    if (statfs(sys, &sf) || sf.f_type != 0x62656572) die("its magic", sf.f_type, 0);

    // The device, and the ways to it.
    reads("devices/virtual/mem/null/dev", "1:3\n");
    reads("devices/virtual/mem/null/uevent", "MAJOR=1\nMINOR=3\nDEVNAME=null\nDEVMODE=0666\n");
    leads("devices/virtual/mem/null/subsystem", "../../../../class/mem");
    leads("class/mem/null", "../../devices/virtual/mem/null");
    leads("dev/char/1:3", "../../devices/virtual/mem/null");
    reads("class/mem/null/dev", "1:3\n");
    reads("class/mem/zero/uevent", "MAJOR=1\nMINOR=5\nDEVNAME=zero\nDEVMODE=0666\n");
    reads("class/mem/full/uevent", "MAJOR=1\nMINOR=7\nDEVNAME=full\nDEVMODE=0666\n");
    reads("class/mem/random/uevent", "MAJOR=1\nMINOR=8\nDEVNAME=random\nDEVMODE=0666\n");
    reads("class/mem/urandom/uevent", "MAJOR=1\nMINOR=9\nDEVNAME=urandom\nDEVMODE=0666\n");
    reads("class/mem/kmsg/uevent", "MAJOR=1\nMINOR=11\nDEVNAME=kmsg\nDEVMODE=0644\n");
    reads("class/tty/tty/uevent", "MAJOR=5\nMINOR=0\nDEVNAME=tty\nDEVMODE=0666\n");
    reads("class/tty/console/uevent", "MAJOR=5\nMINOR=1\nDEVNAME=console\n");
    reads("class/tty/ptmx/uevent", "MAJOR=5\nMINOR=2\nDEVNAME=ptmx\nDEVMODE=0666\n");
    leads("dev/char/5:2", "../../devices/virtual/tty/ptmx");
    struct stat st;
    if (stat(at("devices/virtual/mem/null/uevent"), &st) || (st.st_mode & 07777) != 0644 || st.st_size != 4096 || !S_ISREG(st.st_mode)) die("a uevent file's mode and size", st.st_mode, st.st_size);
    if (stat(at("devices/virtual/mem/null/dev"), &st) || (st.st_mode & 07777) != 0444 || st.st_size != 4096) die("a dev file's mode and size", st.st_mode, st.st_size);
    if (stat(at("devices/virtual/mem/null"), &st) || (st.st_mode & 07777) != 0755 || !S_ISDIR(st.st_mode)) die("a device's directory", st.st_mode, 0);
    if (stat(sys, &st) || (st.st_mode & 07777) != 0555) die("the root's mode", st.st_mode, 0);
    if (lstat(at("class/mem/null"), &st) || !S_ISLNK(st.st_mode)) die("a class's entry", st.st_mode, 0);
    if (stat(at("class/mem"), &st) || !S_ISDIR(st.st_mode) || stat(at("block"), &st) || stat(at("dev/block"), &st) || stat(at("devices/system/cpu/online"), &st) || stat(at("fs"), &st) || stat(at("kernel/uevent_seqnum"), &st)) die("what else is there", errno, 0);
    if (mkdir(at("fs/made"), 0755) == 0 || errno != EPERM) die("mkdir in sysfs", errno, 0);
    if (open(at("devices/virtual/mem/null/made"), O_CREAT | O_WRONLY, 0644) >= 0 || errno != EACCES) die("a file made in sysfs", errno, 0);
    if (open(at("devices/virtual/mem/null/dev"), O_WRONLY) >= 0 || errno != EACCES) die("a dev file opened for writing", errno, 0);

    // The events.
    int s = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    struct sockaddr_nl a = {.nl_family = AF_NETLINK, .nl_groups = 1};
    int on = 1, big = 1 << 20;
    if (s < 0 || setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &big, sizeof big) || setsockopt(s, SOL_SOCKET, SO_PASSCRED, &on, sizeof on) || bind(s, (struct sockaddr *)&a, sizeof a)) die("the uevent socket", s, errno);
    expect(s, "class/mem/null/uevent", "add", "/devices/virtual/mem/null",
           "add@/devices/virtual/mem/null|ACTION=add|DEVPATH=/devices/virtual/mem/null|SUBSYSTEM=mem|SYNTH_UUID=0|MAJOR=1|MINOR=3|DEVNAME=null|DEVMODE=0666");
    expect(s, "devices/virtual/mem/null/uevent", "change\n", "/devices/virtual/mem/null",
           "change@/devices/virtual/mem/null|ACTION=change|DEVPATH=/devices/virtual/mem/null|SUBSYSTEM=mem|SYNTH_UUID=0|MAJOR=1|MINOR=3|DEVNAME=null|DEVMODE=0666");
    expect(s, "devices/virtual/tty/console/uevent", "add", "/devices/virtual/tty/console",
           "add@/devices/virtual/tty/console|ACTION=add|DEVPATH=/devices/virtual/tty/console|SUBSYSTEM=tty|SYNTH_UUID=0|MAJOR=5|MINOR=1|DEVNAME=console");
    expect(s, "class/mem/kmsg/uevent", "add 01234567-89ab-cdef-0123-456789abcdef A=1 B=2", "/devices/virtual/mem/kmsg",
           "add@/devices/virtual/mem/kmsg|ACTION=add|DEVPATH=/devices/virtual/mem/kmsg|SUBSYSTEM=mem|SYNTH_UUID=01234567-89ab-cdef-0123-456789abcdef|SYNTH_ARG_A=1|SYNTH_ARG_B=2|MAJOR=1|MINOR=11|DEVNAME=kmsg|DEVMODE=0644");
    expect(s, "class/mem/zero/uevent", "remove 01234567-89ab-cdef-0123-456789abcdef", "/devices/virtual/mem/zero",
           "remove@/devices/virtual/mem/zero|ACTION=remove|DEVPATH=/devices/virtual/mem/zero|SUBSYSTEM=mem|SYNTH_UUID=01234567-89ab-cdef-0123-456789abcdef|MAJOR=1|MINOR=5|DEVNAME=zero|DEVMODE=0666");
    // What is not an action.
    const char *bad[] = {"bogus", "ad", "", "\n", "add ", "add 0123", "add 01234567x89ab-cdef-0123-456789abcdef", "add 01234567-89ab-cdef-0123-456789abcdef A", "add 01234567-89ab-cdef-0123-456789abcdef A=b-c", "add 01234567-89ab-cdef-0123-456789abcdef  A=1", "add 01234567-89ab-cdef-0123-456789abcdef A="};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        int e = act("class/mem/full/uevent", bad[i]);
        // Nothing written is no write at all.
        if (e != (bad[i][0] ? EINVAL : 0)) die("what is not an action", i, e);
    }
    if (event(s, "/devices/virtual/mem/full")) die("an event for what was refused", 0, 0);

    // What ueventd does with an event: the node, in the tmpfs that is
    // its /dev, which is the device.
    char dev[64], node[96];
    strcpy(dev, "/tmp/sysdev-dev-XXXXXX");
    if (!mkdtemp(dev) || mount("tmpfs", dev, "tmpfs", 0, NULL)) die("a tmpfs for the node", errno, 0);
    snprintf(node, sizeof node, "%s/zero", dev);
    if (mknod(node, S_IFCHR | 0666, makedev(1, 5))) die("mknod", errno, 0);
    int fd = open(node, O_RDONLY);
    char byte = 7;
    if (fd < 0 || read(fd, &byte, 1) != 1 || byte != 0) die("the node as the device", fd, byte);
    close(fd);
    if (umount(dev) || rmdir(dev)) die("umount of the tmpfs", errno, 0);

    close(s);
    if (umount(sys) || rmdir(sys)) die("umount", errno, 0);
    printf("sysdev ok\n");
    return 0;
}
