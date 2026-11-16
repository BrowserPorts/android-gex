// A terminal and the session it belongs to. Android's init gives the
// console to the shell it runs there: the shell's process makes a session
// of its own, opens the terminal and claims it (TIOCSCTTY), and from then
// its group is the terminal's foreground group, which a shell checks
// before it reads (tcgetpgrp) and waits for if it is not. When that shell
// ends init runs another the same way.
//
// On a pseudoterminal:
// - a session leader that claims the terminal is its foreground group;
// - while that session lives, another session's claim is EPERM;
// - once its leader has ended the terminal is free: the next session's
//   claim succeeds and makes it the foreground group.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("ctty: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static char name[64];

// In a child that is a new session: claim the terminal and say how it
// went through the exit status (0 claimed and in the foreground, 1
// refused with EPERM, 2 anything else); `hold` keeps it until told to go.
static pid_t session(int hold_fd) {
    pid_t child = fork();
    if (child < 0) die("fork", errno, 0);
    if (child == 0) {
        if (setsid() < 0) _exit(2);
        int fd = open(name, O_RDWR | O_NOCTTY);
        if (fd < 0) _exit(2);
        if (ioctl(fd, TIOCSCTTY, 0)) _exit(errno == EPERM ? 1 : 2);
        if (tcgetpgrp(fd) != getpgrp() || getpgrp() != getpid()) _exit(3);
        if (hold_fd >= 0) {
            char c;
            // Say it holds the terminal, then wait to be let go.
            if (write(hold_fd, "h", 1) != 1 || read(hold_fd, &c, 1) < 0) _exit(2);
        }
        _exit(0);
    }
    return child;
}

static int ended(pid_t child) {
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) die("a child", status, 0);
    return WEXITSTATUS(status);
}

int main(void) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) || unlockpt(master) || ptsname_r(master, name, sizeof name)) die("a pseudoterminal", errno, 0);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) die("socketpair", errno, 0);
    pid_t first = session(sv[1]);
    char c;
    if (read(sv[0], &c, 1) != 1) die("the first session's claim", errno, 0);
    // Held: another session is refused.
    int r = ended(session(-1));
    if (r != 1) die("a second session's claim while the first lives", r, 0);
    // Let the first go; with its leader ended the terminal is free.
    if (write(sv[0], "g", 1) != 1) die("write", errno, 0);
    if ((r = ended(first)) != 0) die("the first session", r, 0);
    if ((r = ended(session(-1))) != 0) die("a session's claim after the first ended", r, 0);

    printf("ctty ok\n");
    return 0;
}
