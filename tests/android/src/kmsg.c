// /dev/kmsg, the kernel's log as a device: what Android's init and its
// first services write their log to, and logd reads.
//
// - A write is one record. `<N>` before its text gives its level (the low
//   three bits) and facility (the rest); with no facility, or with none
//   at all, the record is a user's, never the kernel's, and with no level
//   it is a warning.
// - A read is one record: `priority,sequence,microseconds,flags;text`,
//   the sequence going up by one a record, a byte that is not printable
//   written \xNN. With none to read a non-blocking read is EAGAIN; into a
//   buffer too small for the record it is EINVAL, and that record is
//   passed over.
// - A record whose write did not end in a newline may still be continued:
//   it is not read until another record follows it.
// - lseek to the end (offset 0) passes every record there is and answers
//   0; any other offset is ESPIPE.
// - A record of more than 1024 bytes is EINVAL.
//
// Other things write to a real kernel's log while this runs, so a record
// is looked for by its text, which carries this process's number.
//
// Needs to open the device for reading and writing (root); without that
// the program says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fd;
static char tag[32];

static void die(const char *what, long a, long b) {
    printf("kmsg: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static void put(const char *prefix, const char *text) {
    char line[256];
    int n = snprintf(line, sizeof line, "%s%s %s", prefix, tag, text);
    if (write(fd, line, n) != n) die("write", n, 0);
}

// The next record of this program's (by its tag): its priority and
// sequence number, and its text after the tag. Whatever else is logged
// meanwhile is passed over.
static void next(unsigned *prio, unsigned long long *seq, char *text, size_t size) {
    char buf[2048];
    for (int tries = 0; tries < 10000; tries++) {
        long n = read(fd, buf, sizeof buf - 1);
        if (n < 0 && errno == EAGAIN) die("no record of ours to read", tries, 0);
        if (n < 0 && errno == EPIPE) continue;
        if (n <= 0) die("read", n, 0);
        buf[n] = 0;
        char *semi = strchr(buf, ';');
        char *mine = semi ? strstr(semi, tag) : NULL;
        if (!mine) continue;
        unsigned long long usec;
        char flag;
        if (sscanf(buf, "%u,%llu,%llu,%c", prio, seq, &usec, &flag) != 4 || flag != '-') die("a record's header", n, 0);
        if (buf[n - 1] != '\n') die("a record's end", buf[n - 1], 0);
        buf[n - 1] = 0;
        snprintf(text, size, "%s", mine + strlen(tag) + 1);
        return;
    }
    die("too many records that are not ours", 0, 0);
}

int main(void) {
    snprintf(tag, sizeof tag, "gex-kmsg-test-%d:", getpid());
    fd = open("/dev/kmsg", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        printf("kmsg: cannot open /dev/kmsg: errno %d\n", errno);
        return errno == EACCES || errno == EPERM || errno == ENOENT ? 77 : 1;
    }
    // Past what is there.
    if (lseek(fd, 0, SEEK_END) != 0) die("lseek to the end", errno, 0);
    if (lseek(fd, 1, SEEK_SET) != -1 || errno != ESPIPE) die("lseek to an offset", errno, ESPIPE);

    put("<6>", "an informational line\n");
    put("", "no level at all");
    put("<27>", "a daemon's error");
    put("<3>", "a \\ and a \x01");

    unsigned prio;
    unsigned long long seq, seq2;
    char text[256];
    next(&prio, &seq, text, sizeof text);
    // LOG_USER and the level; the newline the write ended in is not text.
    if (prio != (1 << 3 | 6) || strcmp(text, "an informational line")) die("the first record", prio, text[0]);
    next(&prio, &seq2, text, sizeof text);
    if (prio != (1 << 3 | 4) || strcmp(text, "no level at all")) die("the record with no level", prio, text[0]);
    if (seq2 <= seq) die("sequence numbers", seq, seq2);
    next(&prio, &seq, text, sizeof text);
    if (prio != 27 || strcmp(text, "a daemon's error")) die("the record with a facility", prio, text[0]);

    // The last had no newline, so it is not to be read yet (unless
    // something else has logged since, which ends it too): then the next
    // write, and it is.
    char buf[2048];
    long n = read(fd, buf, sizeof buf - 1);
    int early = 0;
    while (n > 0) {
        buf[n] = 0;
        early |= strstr(buf, tag) != NULL;
        n = read(fd, buf, sizeof buf - 1);
    }
    if (errno != EAGAIN) die("the read after the last whole record", n, errno);
    put("<6>", "a line longer than the buffer it is first read into\n");
    if (!early) {
        next(&prio, &seq, text, sizeof text);
        if (prio != (1 << 3 | 3) || strcmp(text, "a \\x5c and a \\x01")) {
            printf("kmsg: the escaped record reads '%s'\n", text);
            die("the record with bytes to escape", prio, 0);
        }
    }

    // A buffer too small for the record: EINVAL, and the record is
    // passed over, not kept for the next read.
    char small[16];
    for (;;) {
        n = read(fd, small, sizeof small);
        if (n == -1 && errno == EINVAL) break;
        die("a read into a small buffer", n, errno);
    }
    n = read(fd, buf, sizeof buf - 1);
    while (n > 0) {
        buf[n] = 0;
        if (strstr(buf, tag)) die("the record a small buffer was too small for, read after", n, 0);
        n = read(fd, buf, sizeof buf - 1);
    }
    if (errno != EAGAIN) die("the read after the record passed over", n, errno);

    // The longest record, and one byte more.
    static char line[1026];
    memset(line, 'a', sizeof line);
    memcpy(line, "<6>", 3);
    if (write(fd, line, 1024) != 1024) die("a record of 1024 bytes", errno, 0);
    if (write(fd, line, 1025) != -1 || errno != EINVAL) die("a record of 1025 bytes", errno, EINVAL);

    printf("kmsg ok\n");
    return 0;
}
