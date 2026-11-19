// The device a file is on: st_dev, the number of its filesystem's device.
// Programs take two files with one st_dev and one st_ino for the same
// file. Android's linker does, of the libraries it has loaded, and the
// libraries of two APEXes are in two filesystems that both count their
// inodes from 11.
//
// - A file, a link and a directory in one filesystem have its number, and
//   so has a device node in it (whose own number is st_rdev), opened or
//   not.
// - Each tmpfs mounted has a number of its own, not 0 and not the one of
//   where it is mounted; the directory it is mounted on has the tmpfs's
//   from then on.
// - A directory bound somewhere else is the same filesystem there: the
//   same number, and its files the same inodes.
// - fstat says what stat says, of a file opened, of one opened O_PATH and
//   of one found by its descriptor's link; statx says the same number in
//   its two halves.
// - /proc/self/mountinfo's third field is the number, for each mount.
// - proc is a filesystem with a number of its own.
// - What no path leads to has its kind's: two pipes one number, two
//   sockets one, an eventfd and an epoll one, two memfds one, and the four
//   kinds four numbers, none of them a mounted filesystem's.
//
// Mounts filesystems of its own (root); without that right the program
// says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static char top[64];

static void die(const char *what, long a, long b) {
    printf("statdev: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static const char *at(const char *path) {
    static char full[4][256];
    static int turn;
    char *out = full[turn++ % 4];
    snprintf(out, 256, "%s/%s", top, path);
    return out;
}

static dev_t dev_of(const char *path) {
    struct stat st;
    if (lstat(path, &st)) die(path, errno, 0);
    return st.st_dev;
}

static dev_t dev_of_fd(int fd, const char *what) {
    struct stat st;
    if (fd < 0 || fstat(fd, &st)) die(what, fd, errno);
    return st.st_dev;
}

// The device mountinfo gives for the mount at `where`.
static dev_t listed(const char *where) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) die("mountinfo", errno, 0);
    char line[1024], point[512];
    unsigned id, parent, maj, min;
    dev_t found = 0;
    int seen = 0;
    while (fgets(line, sizeof line, f)) {
        char root[512];
        if (sscanf(line, "%u %u %u:%u %511s %511s", &id, &parent, &maj, &min, root, point) == 6 && !strcmp(point, where)) {
            found = makedev(maj, min);
            seen++;
        }
    }
    fclose(f);
    if (seen != 1) die(where, seen, 0);
    return found;
}

int main(void) {
    if (geteuid() != 0) {
        printf("statdev: needs root\n");
        return 77;
    }
    strcpy(top, "/tmp/statdev-XXXXXX");
    if (!mkdtemp(top)) die("mkdtemp", errno, 0);
    // By the path mountinfo will give: /tmp may be a link (a Mac's is,
    // to private/tmp), and a mount is listed where the link leads.
    char *real = realpath(top, NULL);
    if (!real || strlen(real) >= sizeof top) die("realpath", errno, 0);
    strcpy(top, real);
    free(real);
    dev_t under = dev_of(top);
    if (mount("tmpfs", top, "tmpfs", 0, "mode=0755")) die("a tmpfs", errno, 0);
    dev_t one = dev_of(top);
    if (one == 0 || one == under || major(one) != 0) die("a tmpfs's number", major(one), minor(one));
    if (dev_of(at("..")) != dev_of("/tmp")) die("the directory above the mount", 0, 0);
    if (listed(top) != one) die("mountinfo's number for the tmpfs", major(listed(top)), minor(listed(top)));

    // What is in it.
    int fd = open(at("file"), O_RDWR | O_CREAT | O_EXCL, 0644);
    if (fd < 0 || mkdir(at("dir"), 0755) || symlink("file", at("link")) || mknod(at("null"), S_IFCHR | 0666, makedev(1, 3))) die("making things", errno, 0);
    if (dev_of(at("file")) != one || dev_of(at("dir")) != one || dev_of(at("link")) != one || dev_of(at("null")) != one) die("what is in the tmpfs", 0, 0);
    struct stat st;
    if (stat(at("null"), &st) || st.st_rdev != makedev(1, 3) || st.st_dev != one) die("a device node", st.st_dev, st.st_rdev);
    int null = open(at("null"), O_RDWR);
    if (dev_of_fd(null, "the node, opened") != one || fstat(null, &st) || st.st_rdev != makedev(1, 3)) die("a device node, opened", st.st_dev, st.st_rdev);
    close(null);

    // By descriptor, by O_PATH, by the descriptor's link, by statx.
    if (dev_of_fd(fd, "fstat") != one) die("fstat", 0, 0);
    int path_fd = open(at("file"), O_PATH);
    if (dev_of_fd(path_fd, "fstat of O_PATH") != one) die("fstat of an O_PATH descriptor", 0, 0);
    close(path_fd);
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    if (stat(link, &st) || st.st_dev != one) die("stat by a descriptor's link", st.st_dev, errno);
    int again = open(link, O_RDONLY);
    if (dev_of_fd(again, "the link, opened") != one) die("a descriptor's link, opened", 0, 0);
    close(again);
    struct statx sx;
    if (syscall(SYS_statx, AT_FDCWD, at("file"), 0, STATX_BASIC_STATS, &sx) || makedev(sx.stx_dev_major, sx.stx_dev_minor) != one) die("statx", sx.stx_dev_major, sx.stx_dev_minor);
    memset(&sx, 0, sizeof sx);
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx) || makedev(sx.stx_dev_major, sx.stx_dev_minor) != one) die("statx of a descriptor", sx.stx_dev_major, sx.stx_dev_minor);
    memset(&sx, 0, sizeof sx);
    if (syscall(SYS_statx, AT_FDCWD, at("link"), AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &sx) || makedev(sx.stx_dev_major, sx.stx_dev_minor) != one) die("statx of a link", sx.stx_dev_major, sx.stx_dev_minor);

    // Another tmpfs, in the first: another number.
    if (mkdir(at("two"), 0755) || dev_of(at("two")) != one) die("a directory to mount on", errno, 0);
    if (mount("tmpfs", at("two"), "tmpfs", 0, NULL)) die("a second tmpfs", errno, 0);
    dev_t two = dev_of(at("two"));
    if (two == 0 || two == one || two == under) die("a second tmpfs's number", major(two), minor(two));
    close(open(at("two/inside"), O_WRONLY | O_CREAT, 0644));
    if (dev_of(at("two/inside")) != two || dev_of(at("two/..")) != one) die("across the second mount", 0, 0);
    if (listed(at("two")) != two || listed(top) != one) die("mountinfo's numbers", 0, 0);

    // A directory bound somewhere else: the same filesystem.
    if (mkdir(at("bound"), 0755) || mount(at("dir"), at("bound"), NULL, MS_BIND, NULL)) die("a bind mount", errno, 0);
    close(open(at("dir/inner"), O_WRONLY | O_CREAT, 0644));
    struct stat here, there;
    if (stat(at("dir/inner"), &here) || stat(at("bound/inner"), &there) || here.st_dev != there.st_dev || here.st_ino != there.st_ino || here.st_dev != one) die("a file through a bind mount", here.st_dev, there.st_dev);
    if (dev_of(at("bound")) != one || listed(at("bound")) != one) die("a bind mount's number", 0, 0);

    // proc is a filesystem too. (Each mount of it is one of its own, with
    // its own number, since Linux 5.8; gex has the one at /proc and
    // mounts no other, so that is not asked.)
    dev_t proc = dev_of("/proc");
    if (proc == 0 || proc == one || proc == two || dev_of("/proc/self/status") != proc || dev_of("/proc/self") != proc) die("proc's number", major(proc), minor(proc));
    if (listed("/proc") != proc) die("mountinfo's number for proc", 0, 0);

    // What no path leads to.
    int p[2], q[2], s[2];
    if (pipe(p) || pipe(q) || socketpair(AF_UNIX, SOCK_STREAM, 0, s)) die("pipes and sockets", errno, 0);
    dev_t pipes = dev_of_fd(p[0], "a pipe"), socks = dev_of_fd(s[0], "a socket");
    if (pipes == 0 || dev_of_fd(p[1], "a pipe") != pipes || dev_of_fd(q[0], "a pipe") != pipes) die("the pipes' number", major(pipes), minor(pipes));
    if (socks == 0 || dev_of_fd(s[1], "a socket") != socks) die("the sockets' number", major(socks), minor(socks));
    int inet = socket(AF_INET, SOCK_DGRAM, 0);
    if (dev_of_fd(inet, "an inet socket") != socks) die("an inet socket's number", 0, 0);
    int ev = eventfd(0, 0), ep = epoll_create1(0);
    dev_t anon = dev_of_fd(ev, "an eventfd");
    if (anon == 0 || dev_of_fd(ep, "an epoll") != anon) die("the anonymous inodes' number", major(anon), minor(anon));
    int m1 = memfd_create("one", 0), m2 = memfd_create("two", 0);
    dev_t mem = dev_of_fd(m1, "a memfd");
    if (mem == 0 || dev_of_fd(m2, "a memfd") != mem) die("the memfds' number", major(mem), minor(mem));
    dev_t all[] = {under, one, two, proc, pipes, socks, anon, mem};
    for (unsigned i = 0; i < sizeof all / sizeof *all; i++)
        for (unsigned j = i + 1; j < sizeof all / sizeof *all; j++)
            if (all[i] == all[j]) die("two filesystems with one number", i, j);

    close(fd);
    if (umount(at("bound")) || umount(at("two")) || umount(top) || rmdir(top)) die("umount", errno, 0);
    printf("statdev ok\n");
    return 0;
}
