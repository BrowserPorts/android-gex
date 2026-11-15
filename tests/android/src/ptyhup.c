// A pseudoterminal's master hears its other end close. Android's init
// runs programs through logwrap, which gives a child a pseudoterminal for
// its output, reads the master while poll says POLLIN, and takes POLLHUP
// to mean the child is done: a master that only ever says POLLIN, with
// nothing to read, is polled for ever.
//
// A child makes itself a session, opens the slave (which becomes its
// terminal), writes a line and exits. The parent, at the master:
// - poll says POLLIN while the line is unread, and the line is read;
// - with nothing left and the child gone, poll says POLLHUP and not
//   POLLIN, whether or not POLLIN was asked for;
// - read then fails with EIO, and goes on failing so;
// - the child is there to be waited for.
// And a master nobody has opened the slave of says nothing: a poll of it
// with a time limit runs out.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("ptyhup: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

int main(void) {
    int master = posix_openpt(O_RDWR | O_CLOEXEC);
    char name[64];
    if (master < 0 || grantpt(master) || unlockpt(master) || ptsname_r(master, name, sizeof name)) die("a pseudoterminal", errno, 0);

    // Nobody at the other end yet: nothing to say.
    struct pollfd p = {master, POLLIN, 0};
    if (poll(&p, 1, 50) != 0) die("a master with no slave opened", p.revents, 0);

    pid_t child = fork();
    if (child < 0) die("fork", errno, 0);
    if (child == 0) {
        setsid();
        int slave = open(name, O_RDWR);
        if (slave < 0) _exit(2);
        if (write(slave, "line\n", 5) != 5) _exit(3);
        _exit(0);
    }

    // The line, then the end.
    char buf[64];
    size_t got = 0;
    for (;;) {
        p.revents = 0;
        if (poll(&p, 1, 20000) != 1) die("poll of the master", p.revents, got);
        if (p.revents & POLLIN) {
            ssize_t n = read(master, buf + got, sizeof buf - got);
            if (n > 0) {
                got += n;
                continue;
            }
            // Readable with nothing to read is the end, if POLLHUP says so.
            if (!(p.revents & POLLHUP)) die("POLLIN with nothing to read and no POLLHUP", n, errno);
        }
        if (p.revents & POLLHUP) break;
        die("neither POLLIN nor POLLHUP", p.revents, 0);
    }
    // A terminal makes a newline a carriage return and a newline.
    if (got != 6 || memcmp(buf, "line\r\n", 6)) die("what the child wrote", got, buf[0]);

    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) die("the child", status, 0);
    // Now for certain: nothing to read, the other end closed.
    p.revents = 0;
    if (poll(&p, 1, 20000) != 1 || p.revents != POLLHUP) die("poll after the end", p.revents, 0);
    p.events = 0;
    p.revents = 0;
    if (poll(&p, 1, 20000) != 1 || p.revents != POLLHUP) die("poll for nothing, after the end", p.revents, 0);
    for (int i = 0; i < 2; i++)
        if (read(master, buf, sizeof buf) != -1 || errno != EIO) die("read after the end", errno, i);

    printf("ptyhup ok\n");
    return 0;
}
