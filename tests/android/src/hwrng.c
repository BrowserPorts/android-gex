// The hardware random number generator's device (drivers/char/hw_random,
// misc 10:183), which Android's prng_seeder reads: open for reading alone,
// a read of what is asked from the generator in use (ENODEV with none),
// a position that stays 0, and the core's attributes in sysfs: the
// generator in use, those there are, whether a program chose, its
// quality. With a generator (a virtio-rng: the emulator's, a VM's), the
// test chooses none and then the core's best again, as rng_current takes
// them. Run as root (mknod, mount, the attributes).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int failed;
static char sys[64], node[64];

static void want(const char *what, long r, int err) {
    int got = r >= 0 ? 0 : errno;
    if (got != err) {
        printf("hwrng: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

// An attribute's text, or "" with errno set.
static const char *attr(const char *name) {
    static char buf[256];
    char path[160];
    snprintf(path, sizeof path, "%s/class/misc/hw_random/%s", sys, name);
    int fd = open(path, O_RDONLY);
    buf[0] = 0;
    if (fd < 0) return buf;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    int e = errno;
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    errno = n < 0 ? e : 0;
    return buf;
}

static long store(const char *name, const char *text) {
    char path[160];
    snprintf(path, sizeof path, "%s/class/misc/hw_random/%s", sys, name);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    long r = write(fd, text, strlen(text));
    int e = errno;
    close(fd);
    errno = e;
    return r;
}

static void is(const char *what, const char *got, const char *expect) {
    if (strcmp(got, expect)) {
        printf("hwrng: %s: want \"%s\", got \"%s\"\n", what, expect, got);
        failed = 1;
    }
}

// A read from the device: all of it with a generator, ENODEV without.
static void reads(const char *what, int have) {
    unsigned char buf[100];
    for (int flags = 0; flags < 2; flags++) {
        int fd = open(node, O_RDONLY | (flags ? O_NONBLOCK : 0));
        if (fd < 0) {
            printf("hwrng: open (errno %d)\n", errno);
            failed = 1;
            return;
        }
        memset(buf, 0, sizeof buf);
        long n = read(fd, buf, sizeof buf);
        if (have) {
            // A read that waits has all it asks for. One that does not has
            // what the core and the device hold now, which depends on
            // timing (the kernel's own hwrng thread reads the device too):
            // all, some, or EAGAIN.
            int ok = flags ? (n > 0 && n <= (long)sizeof buf) || (n < 0 && errno == EAGAIN) : n == (long)sizeof buf;
            int zeros = 0;
            for (int i = 0; i < (n > 0 ? n : 0); i++) zeros += buf[i] == 0;
            if (!ok || zeros > 4 + n / 5) {
                printf("hwrng: %s: a read%s gave %ld (errno %d), %d zero bytes\n", what, flags ? " not waiting" : "", n, errno, zeros);
                failed = 1;
            }
            if (lseek(fd, 0, SEEK_CUR) != 0 || lseek(fd, 10, SEEK_SET) != 0) {
                printf("hwrng: %s: the position moved\n", what);
                failed = 1;
            }
        } else {
            want(what, n, ENODEV);
        }
        want("an empty read", read(fd, buf, 0), 0);
        close(fd);
    }
}

int main(void) {
    char base[] = "/tmp/hwrng-XXXXXX";
    if (!mkdtemp(base) || mount("tmpfs", base, "tmpfs", 0, NULL)) {
        printf("hwrng: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(sys, sizeof sys, "%s/sys", base);
    snprintf(node, sizeof node, "%s/hw_random", base);
    if (mkdir(sys, 0755) || mount("sysfs", sys, "sysfs", 0, NULL) || mknod(node, S_IFCHR | 0400, makedev(10, 183))) {
        printf("hwrng: setup (errno %d)\n", errno);
        return 1;
    }

    // The device, as its core registers it.
    char path[160];
    snprintf(path, sizeof path, "%s/class/misc/hw_random/uevent", sys);
    int fd = open(path, O_RDONLY);
    char ev[256] = {0};
    if (fd < 0 || read(fd, ev, sizeof ev - 1) < 0) {
        printf("hwrng: uevent (errno %d)\n", errno);
        return 1;
    }
    close(fd);
    is("uevent", ev, "MAJOR=10\nMINOR=183\nDEVNAME=hwrng\n");

    want("open to write", open(node, O_WRONLY), EINVAL);
    want("open to read and write", open(node, O_RDWR), EINVAL);

    char current[64];
    snprintf(current, sizeof current, "%s", attr("rng_current"));
    is("rng_selected", attr("rng_selected"), "0\n");
    if (!strcmp(current, "none\n")) {
        is("rng_available", attr("rng_available"), "none\n");
        attr("rng_quality");
        want("rng_quality with none", errno ? -1 : 0, ENODEV);
        reads("with none", 0);
    } else {
        char available[96];
        snprintf(available, sizeof available, "%.*s none\n", (int)strlen(current) - 1, current);
        is("rng_available", attr("rng_available"), available);
        is("rng_quality", attr("rng_quality"), "1024\n");
        reads("with one", 1);
        // None, chosen: nothing to read, and the choice is the program's.
        want("choosing none", store("rng_current", "none\n"), 0);
        is("rng_current after none", attr("rng_current"), "none\n");
        is("rng_selected after none", attr("rng_selected"), "1\n");
        reads("with none chosen", 0);
        want("a quality with none", store("rng_quality", "512\n"), ENODEV);
        // A name no generator has changes nothing.
        want("choosing one not there", store("rng_current", "nothing.0\n"), 0);
        is("rng_current after one not there", attr("rng_current"), "none\n");
        // Empty: the core's best again, and its choice.
        want("the core's best", store("rng_current", "\n"), 0);
        is("rng_current again", attr("rng_current"), current);
        is("rng_selected again", attr("rng_selected"), "0\n");
        want("a quality too high", store("rng_quality", "1025\n"), EINVAL);
        want("a quality too short", store("rng_quality", "5"), EINVAL);
        want("a quality not a number", store("rng_quality", "x1\n"), EINVAL);
        is("rng_quality kept", attr("rng_quality"), "1024\n");
        reads("with one again", 1);
    }

    umount2(sys, MNT_DETACH);
    umount2(base, MNT_DETACH);
    rmdir(base);
    if (failed) return 1;
    printf("hwrng ok\n");
    return 0;
}
