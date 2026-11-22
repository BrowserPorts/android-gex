// AF_KEY sockets (net/key/af_key.c), as Android's network stack uses one:
// made and closed at once, to wait out an RCU grace period
// (synchronizeKernelRCU), which the network statistics service needs and
// dies without. Made as pfkey_create makes one: CAP_NET_ADMIN first, then
// SOCK_RAW, then PF_KEY_V2. Nothing is sent to a new socket, so a
// non-blocking read finds nothing. Run as root.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/pfkeyv2.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int failed;

static void want(const char *what, int r, int err) {
    int got = r >= 0 ? 0 : errno;
    if (got != err) {
        printf("pfkey: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
    if (r >= 0) close(r);
}

int main(void) {
    int s = socket(AF_KEY, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, PF_KEY_V2);
    if (s < 0) {
        printf("pfkey: socket (errno %d)\n", errno);
        return 1;
    }
    char buf[64];
    if (read(s, buf, sizeof buf) != -1 || errno != EAGAIN) {
        printf("pfkey: a read with nothing sent (errno %d)\n", errno);
        failed = 1;
    }
    if (close(s)) {
        printf("pfkey: close (errno %d)\n", errno);
        failed = 1;
    }
    want("a datagram socket", socket(AF_KEY, SOCK_DGRAM, PF_KEY_V2), ESOCKTNOSUPPORT);
    want("protocol 0", socket(AF_KEY, SOCK_RAW, 0), EPROTONOSUPPORT);
    pid_t child = fork();
    if (child == 0) {
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) _exit(2);
        failed = 0;
        want("without CAP_NET_ADMIN", socket(AF_KEY, SOCK_RAW, PF_KEY_V2), EPERM);
        want("without CAP_NET_ADMIN, a datagram socket", socket(AF_KEY, SOCK_DGRAM, 0), EPERM);
        _exit(failed);
    }
    int st;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("pfkey: the unprivileged child (status %#x)\n", st);
        failed = 1;
    }
    if (failed) return 1;
    printf("pfkey ok\n");
    return 0;
}
