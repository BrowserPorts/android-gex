// A socket made for another program: init makes each of a service's
// sockets (stream, datagram or seqpacket), binds it at /dev/socket/<name>
// with the whole sockaddr_un as the address's length, gives the file its
// owner and mode, may start it listening, and runs the service with the
// descriptor open and its number in the environment. The service
// (android_get_control_socket) trusts the descriptor only if it is still
// open and getsockname says the path init bound it at; lmkd and logd end
// or go without their sockets otherwise.
//
// For each of the three kinds, as init and then as the service:
// - bind with the address's length the size of the whole structure;
//   getsockname gives the path, and a length that ends just after it;
// - the socket's file is a socket, and takes an owner (lchown) and a
//   mode (fchmodat with AT_SYMLINK_NOFOLLOW);
// - SO_PASSCRED set before the bind is still set after it;
// - the program run with the descriptor open (this one, again) finds it
//   open (F_GETFD), of the kind it was made (SO_TYPE), and bound where
//   it was.
// A datagram sent to the datagram socket is read with who sent it
// (SCM_CREDENTIALS: the sender's process, user and group).
// A stream and a seqpacket socket are listening when init says so
// (SO_ACCEPTCONN), and a client that connects to the path is accepted.
//
// Needs root (a tmpfs of its own, and the owner it gives); exits 77
// without.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what, long a, long b) {
    printf("ctlsock: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

// The service's half: is descriptor `fd` a socket of kind `type`, bound
// at `path`, listening or not as `listening` says?
static void service(int fd, int type, const char *path, int listening) {
    if (fcntl(fd, F_GETFD) < 0) die("the descriptor, in the program run", fd, errno);
    struct sockaddr_un addr;
    memset(&addr, 0xff, sizeof addr);
    socklen_t len = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &len)) die("getsockname", fd, errno);
    if (addr.sun_family != AF_UNIX || strcmp(addr.sun_path, path)) die("the path getsockname gives", addr.sun_family, addr.sun_path[0]);
    if (len != offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) die("the length getsockname gives", len, strlen(path));
    int got = -1;
    socklen_t n = sizeof got;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &got, &n) || got != type) die("SO_TYPE", got, type);
    if (getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &got, &n) || got != 1) die("SO_PASSCRED", got, 0);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &got, &n) || got != listening) die("SO_ACCEPTCONN", got, listening);
    if (type == SOCK_DGRAM) {
        // A datagram comes with who sent it, since the socket asked
        // (SO_PASSCRED): logd takes a line of log only so.
        int client = socket(AF_UNIX, SOCK_DGRAM, 0);
        struct sockaddr_un to = {.sun_family = AF_UNIX};
        strcpy(to.sun_path, path);
        if (client < 0 || sendto(client, "log", 3, 0, (struct sockaddr *)&to, sizeof to) != 3) die("a datagram sent", errno, 0);
        char buf[8];
        union {
            char bytes[CMSG_SPACE(sizeof(struct ucred))];
            struct cmsghdr align;
        } control;
        struct iovec iov = {buf, sizeof buf};
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof control.bytes};
        if (recvmsg(fd, &msg, 0) != 3 || memcmp(buf, "log", 3)) die("the datagram", errno, 0);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS || c->cmsg_len != CMSG_LEN(sizeof(struct ucred))) die("the datagram's control message", msg.msg_controllen, c ? c->cmsg_type : -1);
        struct ucred who;
        memcpy(&who, CMSG_DATA(c), sizeof who);
        if (who.pid != getpid() || who.uid != geteuid() || who.gid != getegid()) die("who sent the datagram", who.pid, who.uid);
        close(client);
    }
    if (listening) {
        int client = socket(AF_UNIX, type, 0);
        struct sockaddr_un to = {.sun_family = AF_UNIX};
        strcpy(to.sun_path, path);
        if (client < 0 || connect(client, (struct sockaddr *)&to, sizeof to)) die("a client's connect", type, errno);
        int peer = accept(fd, NULL, NULL);
        if (peer < 0 || write(client, "hi", 2) != 2) die("accept", type, errno);
        char buf[4];
        if (read(peer, buf, sizeof buf) != 2 || memcmp(buf, "hi", 2)) die("what the client sent", type, errno);
        close(peer);
        close(client);
    }
}

int main(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[1], "service")) {
        service(atoi(argv[2]), atoi(argv[3]), argv[4], getenv("CTLSOCK_LISTENING") != NULL);
        return 0;
    }
    if (geteuid() != 0) {
        printf("ctlsock: needs root\n");
        return 77;
    }
    // In a tmpfs of its own, as /dev/socket is one.
    char dir[] = "/tmp/ctlsock-XXXXXX";
    if (!mkdtemp(dir) || mount("tmpfs", dir, "tmpfs", 0, "mode=0755")) die("a tmpfs", errno, 0);
    int types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
    for (int i = 0; i < 3; i++) {
        int type = types[i], listening = type != SOCK_DGRAM;
        struct sockaddr_un addr = {.sun_family = AF_UNIX};
        snprintf(addr.sun_path, sizeof addr.sun_path, "%s/sock%d", dir, i);
        int fd = socket(PF_UNIX, type, 0);
        int on = 1;
        if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof on)) die("socket", type, errno);
        if (bind(fd, (struct sockaddr *)&addr, sizeof addr)) die("bind", type, errno);
        struct stat st;
        if (lchown(addr.sun_path, 1036, 1036) || fchmodat(AT_FDCWD, addr.sun_path, 0660, AT_SYMLINK_NOFOLLOW)) die("the file's owner and mode", type, errno);
        if (lstat(addr.sun_path, &st) || !S_ISSOCK(st.st_mode) || (st.st_mode & 07777) != 0660 || st.st_uid != 1036 || st.st_gid != 1036) die("the socket's file", st.st_mode, st.st_uid);
        if (listening && listen(fd, 1 << 30)) die("listen", type, errno);
        service(fd, type, addr.sun_path, listening);
        // And in a program run with it.
        pid_t child = fork();
        if (child < 0) die("fork", errno, 0);
        if (child == 0) {
            char a[16], b[16];
            snprintf(a, sizeof a, "%d", fd);
            snprintf(b, sizeof b, "%d", type);
            if (listening) setenv("CTLSOCK_LISTENING", "1", 1);
            execl("/proc/self/exe", argv[0], "service", a, b, addr.sun_path, (char *)NULL);
            _exit(126);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
            printf("ctlsock: the program run with kind %d said no (status %x)\n", type, status);
            return 1;
        }
        close(fd);
        if (unlink(addr.sun_path)) die("unlink", type, errno);
    }
    if (umount(dir) || rmdir(dir)) die("umount", errno, 0);
    printf("ctlsock ok\n");
    return 0;
}
