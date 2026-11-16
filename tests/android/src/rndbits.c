// vm.mmap_rnd_bits: how many bits of a mapping's address the kernel
// makes random, a number root may set within what the kernel was built
// for. Android's init sets it as high as it will go at every boot, by
// writing 33 and then one less each time until what it reads back, from
// a descriptor it opened before, is what it wrote; if 24 is not taken it
// stops the boot.
//
// - The file is a regular one, root's alone to read and write (0600).
// - A number in range is taken and is what a read then gives, a read
//   through a descriptor opened before the write as much as a new one.
// - The range is 18 to 24 (a 39-bit address space, Android's kernels) or
//   18 to 33 (48 bits): one outside it is EINVAL and changes nothing.
// - The number is read as the kernel reads numbers: space before it,
//   0x for sixteen and a leading 0 for eight, the end or space after it,
//   and nothing looked at after that (a write of two numbers is a short
//   write of the first). Letters, a minus sign's number, a number with
//   letters on it and nothing at all are EINVAL.
//
// Needs root; what the setting was is put back.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH "/proc/sys/vm/mmap_rnd_bits"

static void die(const char *what, long a, long b) {
    printf("rndbits: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

// How much of the last write was taken.
static ssize_t taken;

// Write `text` through a descriptor of its own: 0, or the errno.
static int put(const char *text) {
    int fd = open(PATH, O_WRONLY);
    if (fd < 0) die("open to write", errno, 0);
    taken = write(fd, text, strlen(text));
    int e = taken < 0 ? errno : 0;
    close(fd);
    return e;
}

static long get(int fd) {
    char buf[32] = {0};
    if (lseek(fd, 0, SEEK_SET) != 0) die("lseek", errno, 0);
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n < 2 || buf[n - 1] != '\n') die("a read", n, buf[0]);
    return strtol(buf, NULL, 10);
}

int main(void) {
    if (geteuid() != 0) {
        printf("rndbits: needs root\n");
        return 77;
    }
    struct stat st;
    if (stat(PATH, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 07777) != 0600 || st.st_uid != 0) die("the file", st.st_mode, st.st_uid);
    // One descriptor for every read, opened before any write, as init's.
    int in = open(PATH, O_RDONLY);
    if (in < 0) die("open to read", errno, 0);
    long was = get(in);

    // As init: from 33 down until one is taken.
    long max = 33;
    char text[32];
    for (; max >= 18; max--) {
        snprintf(text, sizeof text, "%ld\n", max);
        int e = put(text);
        if (e == 0 && get(in) == max) break;
        if (e != EINVAL) die("a number too large", e, max);
    }
    if (max != 24 && max != 33) die("the most it takes", max, 0);
    snprintf(text, sizeof text, "%ld\n", max + 1);
    if (put(text) != EINVAL || get(in) != max) die("one more than the most", get(in), max);
    if (put("18\n") || get(in) != 18) die("the least", get(in), 0);
    if (put("17\n") != EINVAL || get(in) != 18) die("one less than the least", get(in), 0);
    if (put("-1\n") != EINVAL || put("0\n") != EINVAL || get(in) != 18) die("a number far too small", get(in), 0);

    // How a number may be written.
    if (put("22") || get(in) != 22) die("no newline", get(in), 0);
    if (put(" \t21\n") || get(in) != 21) die("space before it", get(in), 0);
    if (put("024\n") || get(in) != 20) die("a leading 0 is base eight", get(in), 0);
    if (put("0x17\n") || get(in) != 23) die("0x is base sixteen", get(in), 0);
    // The first of two is taken, with the space after it: a short write.
    if (put("19 7\n") || taken != 3 || get(in) != 19) die("the first number of two", get(in), taken);
    if (put(" 20\n\n") || taken != 5 || get(in) != 20) die("all of a write of one number", get(in), taken);
    if (put("abc\n") != EINVAL || put("21x\n") != EINVAL || put("\n") != EINVAL || get(in) != 20) die("what is not a number", get(in), 0);
    // And a descriptor opened now reads what the old one does.
    int again = open(PATH, O_RDONLY);
    if (again < 0 || get(again) != 20) die("a new descriptor", errno, 0);
    close(again);

    snprintf(text, sizeof text, "%ld\n", was);
    if (put(text) || get(in) != was) die("putting it back", get(in), was);
    close(in);
    printf("rndbits ok\n");
    return 0;
}
