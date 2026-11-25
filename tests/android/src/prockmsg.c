// /proc/kmsg, the kernel's log read once, as Android's logd reads it (init
// opens it for logd, which takes `<N>[seconds.microseconds] text` lines):
// mode 0400 root's to start, emptied by reading (O_NONBLOCK: EAGAIN when
// there is nothing more), a record written to /dev/kmsg arrives as
// `<14>[%5lu.%06lu] text\n` (facility user, level info), a read too short
// for the next record takes the first bytes of it and the next read the
// rest, a zero-length read with nothing unread is EAGAIN (non-blocking),
// and poll says when there is something.
// chown and chmod hold. As root; it reads (and so takes) what the log
// holds unread.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("prockmsg: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

int main(void) {
    struct stat st;
    want("stat", stat("/proc/kmsg", &st), 0);
    want("its mode", st.st_mode & 07777, 0400);
    want("its owner", st.st_uid, 0);
    int fd = open("/proc/kmsg", O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        printf("prockmsg: open: %d\n", errno);
        return 1;
    }
    // Take what is unread.
    char buf[8192];
    while (read(fd, buf, sizeof buf) > 0) {
    }
    want("nothing unread", read(fd, buf, sizeof buf) < 0 ? errno : 0, EAGAIN);
    struct pollfd p = {.fd = fd, .events = POLLIN};
    want("poll with nothing", poll(&p, 1, 0), 0);
    // With nothing unread a non-blocking read is EAGAIN whatever its
    // length (kmsg_read asks before do_syslog's 0 for a zero length).
    want("a zero-length read with nothing unread", read(fd, buf, 0) < 0 ? errno : 0, EAGAIN);

    int k = open("/dev/kmsg", O_WRONLY);
    const char *line = "<14>gex prockmsg marker 0123456789\n";
    want("write to /dev/kmsg", write(k, line, strlen(line)), (long)strlen(line));
    want("poll with a record", poll(&p, 1, 0), 1);
    // With one unread, a zero-length read is 0 and takes nothing.
    want("a zero-length read with a record", read(fd, buf, 0), 0);
    // A read of 10 bytes: the record's first 10; then the rest.
    char a[16], b[512];
    long n = read(fd, a, 10);
    want("a short read", n, 10);
    long m = read(fd, b, sizeof b - 1);
    if (n == 10 && m > 0) {
        char whole[600];
        memcpy(whole, a, 10);
        memcpy(whole + 10, b, m);
        whole[10 + m] = 0;
        unsigned long s = 0, us = 0;
        char text[256] = "";
        int got = sscanf(whole, "<14>[%5lu.%6lu] %255[^\n]\n", &s, &us, text);
        want("its fields", got, 3);
        if (strcmp(text, "gex prockmsg marker 0123456789")) {
            printf("prockmsg: its text: \"%s\"\n", whole);
            failed = 1;
        }
        want("one line", (long)strlen(whole), (long)(strchr(whole, '\n') - whole + 1));
        // The time's form: five places of seconds, a point, six of microseconds.
        want("the time's form", whole[4] == '[' && whole[10] == '.' && whole[17] == ']' && whole[18] == ' ', 1);
    } else {
        printf("prockmsg: the rest: %ld (%d)\n", m, errno);
        failed = 1;
    }
    want("taken", read(fd, buf, sizeof buf) < 0 ? errno : 0, EAGAIN);
    close(k);

    // chmod and chown hold (Android's init: root:system, 0440).
    want("chmod", chmod("/proc/kmsg", 0440), 0);
    want("chown", chown("/proc/kmsg", 0, 1000), 0);
    stat("/proc/kmsg", &st);
    want("the mode set", st.st_mode & 07777, 0440);
    want("the group set", st.st_gid, 1000);
    chmod("/proc/kmsg", 0400);
    chown("/proc/kmsg", 0, 0);
    close(fd);
    if (!failed) printf("prockmsg ok\n");
    return failed;
}
