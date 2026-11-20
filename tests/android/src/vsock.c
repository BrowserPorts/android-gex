// AF_VSOCK stream sockets as a guest of a virtio-vsock host has them, the
// way the Android emulator image's pipe library uses them
// (qemu_pipe_guest.cpp): a stream to the host (CID 2) at port 5000, the
// emulator's pipe services, and port 5001, which the host always resets.
//
// What any such guest sees, checked against Linux 7.0 under a host with no
// service at those ports:
// - socket(AF_VSOCK, SOCK_STREAM) with protocol 0 or AF_VSOCK; another
//   protocol is EPROTONOSUPPORT;
// - unbound, getsockname gives CID and port -1; getpeername is ENOTCONN;
//   reads and writes are ENOTCONN; shutdown is ENOTCONN;
// - connect with a short address, another family, or unknown flags is
//   EINVAL; to a port the host resets, ECONNRESET, with the socket bound to
//   an ephemeral port above 1023 all the same, which a second connect keeps.
// Then, where the host is the emulator (port 5000 accepts): the sensors
// service, as the image's sensors HAL asks it, says it has no sensors;
// after a shutdown, reads are 0 and writes EPIPE.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

static void die(const char *what, long a, long b) {
    printf("vsock: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static struct sockaddr_vm to(unsigned cid, unsigned port) {
    struct sockaddr_vm a;
    memset(&a, 0, sizeof a);
    a.svm_family = AF_VSOCK;
    a.svm_cid = cid;
    a.svm_port = port;
    return a;
}

static int connect_to(int fd, unsigned cid, unsigned port) {
    struct sockaddr_vm a = to(cid, port);
    return connect(fd, (struct sockaddr *)&a, sizeof a);
}

static int read_fully(int fd, char *buf, int n) {
    for (int got = 0; got < n;) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int fd = socket(AF_VSOCK, SOCK_STREAM, AF_VSOCK);
    if (fd < 0) {
        if (errno == EAFNOSUPPORT) {
            printf("vsock: the kernel has no vsock\n");
            return 77;
        }
        die("socket", fd, errno);
    }
    close(fd);
    fd = socket(AF_VSOCK, SOCK_STREAM, 1);
    if (fd >= 0 || errno != EPROTONOSUPPORT) die("another protocol", fd, errno);
    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) die("socket", fd, errno);
    close(fd);
    fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_vm name;
    socklen_t len = sizeof name;
    memset(&name, 0x55, sizeof name);
    if (getsockname(fd, (struct sockaddr *)&name, &len) || len != sizeof name || name.svm_family != AF_VSOCK || name.svm_cid != VMADDR_CID_ANY || name.svm_port != VMADDR_PORT_ANY) die("getsockname, unbound", name.svm_cid, name.svm_port);
    len = sizeof name;
    if (getpeername(fd, (struct sockaddr *)&name, &len) == 0 || errno != ENOTCONN) die("getpeername, unconnected", 0, errno);
    char buf[64];
    if (read(fd, buf, sizeof buf) != -1 || errno != ENOTCONN) die("read, unconnected", 0, errno);
    if (write(fd, "x", 1) != -1 || errno != ENOTCONN) die("write, unconnected", 0, errno);
    if (shutdown(fd, SHUT_RDWR) == 0 || errno != ENOTCONN) die("shutdown, unconnected", 0, errno);

    struct sockaddr_vm a = to(VMADDR_CID_HOST, 5001);
    if (connect(fd, (struct sockaddr *)&a, sizeof a - 1) == 0 || errno != EINVAL) die("connect, a short address", 0, errno);
    a.svm_family = AF_UNIX;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0 || errno != EINVAL) die("connect, another family", 0, errno);
    a = to(VMADDR_CID_HOST, 5001);
    a.svm_flags = 2;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0 || errno != EINVAL) die("connect, unknown flags", 0, errno);
    if (connect_to(fd, VMADDR_CID_HOST, 5001) == 0 || errno != ECONNRESET) die("connect to the port the host resets", 0, errno);
    len = sizeof name;
    if (getsockname(fd, (struct sockaddr *)&name, &len) || name.svm_cid != VMADDR_CID_ANY || name.svm_port <= 1023 || name.svm_port == VMADDR_PORT_ANY) die("getsockname, after a reset", name.svm_cid, name.svm_port);
    unsigned port = name.svm_port;
    if (connect_to(fd, VMADDR_CID_HOST, 5001) == 0 || errno != ECONNRESET) die("connect again", 0, errno);
    len = sizeof name;
    if (getsockname(fd, (struct sockaddr *)&name, &len) || name.svm_port != port) die("the port kept", port, name.svm_port);
    close(fd);

    // The emulator's services, if this host is the emulator.
    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (connect_to(fd, VMADDR_CID_HOST, 5000)) {
        if (errno != ECONNRESET) die("connect to port 5000", 0, errno);
        printf("vsock: no emulator at port 5000\n");
    } else {
        len = sizeof name;
        if (getpeername(fd, (struct sockaddr *)&name, &len) || name.svm_cid != VMADDR_CID_HOST || name.svm_port != 5000) die("getpeername", name.svm_cid, name.svm_port);
        if (connect_to(fd, VMADDR_CID_HOST, 5000) == 0 || errno != EISCONN) die("connect, connected", 0, errno);
        static const char hello[] = "pipe:qemud:sensors";
        if (write(fd, hello, sizeof hello) != sizeof hello) die("the connection string", 0, errno);
        if (write(fd, "000clist-sensors", 16) != 16) die("list-sensors", 0, errno);
        if (read_fully(fd, buf, 4) || memcmp(buf, "0001", 4) || read_fully(fd, buf, 1) || buf[0] != '0') die("the sensors' mask", buf[0], 0);
        printf("vsock: the emulator's sensors service says there are none\n");
        if (shutdown(fd, SHUT_WR)) die("shutdown", 0, errno);
        if (read(fd, buf, sizeof buf) != 0) die("read after shutdown", 0, errno);
        if (write(fd, "x", 1) != -1 || errno != EPIPE) die("write after shutdown", 0, errno);
    }
    close(fd);
    printf("vsock ok\n");
    return 0;
}
