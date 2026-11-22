// AF_VSOCK stream sockets as a guest of a virtio-vsock host has them, the
// way the Android emulator image's pipe library uses them
// (qemu_pipe_guest.cpp): a stream to the host (CID 2) at port 5000, the
// emulator's pipe services, and port 5001, which the host always resets.
//
// What any such guest sees, checked against Linux 7.0 (as root, which a
// child's setuid needs) under a host with no service at those ports:
// - socket(AF_VSOCK, SOCK_STREAM) with protocol 0 or AF_VSOCK; another
//   protocol is EPROTONOSUPPORT;
// - unbound, getsockname gives CID and port -1; getpeername is ENOTCONN;
//   reads and writes are ENOTCONN; shutdown is ENOTCONN;
// - connect with a short address, another family, or unknown flags is
//   EINVAL; to a port the host resets, ECONNRESET, with the socket bound to
//   an ephemeral port above 1023 all the same, which a second connect keeps;
//   a socket bound so binds no more (EINVAL) but may listen;
// - bind: a CID not the guest's EADDRNOTAVAIL, a port up to 1023 EACCES
//   without CAP_NET_BIND_SERVICE, a bound port EADDRINUSE until its socket
//   is closed; listen and accept EINVAL unless bound and listening; a
//   listener polls as nothing, its accept is EAGAIN without waiting and
//   waits otherwise, and connect, getpeername, shutdown, read and write on
//   it are EINVAL or ENOTCONN.
// Then, where the host is the emulator (port 5000 accepts): the sensors
// service, as the image's sensors HAL asks it, says it has no sensors;
// after a shutdown, reads are 0 and writes EPIPE. The boot-properties
// service, as qemu-props asks it, lists none (the end-of-list NUL alone:
// this emulator is given no properties); the misc pipe answers a heartbeat
// OK, random bytes as many as asked, and anything else KO.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
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

static int bind_to(int fd, unsigned cid, unsigned port) {
    struct sockaddr_vm a = to(cid, port);
    return bind(fd, (struct sockaddr *)&a, sizeof a);
}

static void sleep_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&t, 0);
}

// A listener, as adbd makes its `vsock:5555`.
static void listener(void) {
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (listen(s, 4) == 0 || errno != EINVAL) die("listen, unbound", 0, errno);
    if (accept(s, 0, 0) != -1 || errno != EINVAL) die("accept, not listening", 0, errno);
    struct sockaddr_vm a = to(VMADDR_CID_ANY, 15555);
    if (bind(s, (struct sockaddr *)&a, sizeof a - 1) == 0 || errno != EINVAL) die("bind, a short address", 0, errno);
    if (bind_to(s, VMADDR_CID_HOST, 15555) == 0 || errno != EADDRNOTAVAIL) die("bind, the host's CID", 0, errno);
    if (bind_to(s, 0x12345, 15555) == 0 || errno != EADDRNOTAVAIL) die("bind, a CID not the guest's", 0, errno);
    pid_t child = fork();
    if (child == 0) {
        if (setuid(65534)) _exit(2);
        int u = socket(AF_VSOCK, SOCK_STREAM, 0);
        _exit(bind_to(u, VMADDR_CID_ANY, 555) == -1 && errno == EACCES ? 0 : 1);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) die("bind, a reserved port unprivileged", status, 0);
    if (bind_to(s, VMADDR_CID_ANY, 15555)) die("bind", 0, errno);
    struct sockaddr_vm name;
    socklen_t len = sizeof name;
    if (getsockname(s, (struct sockaddr *)&name, &len) || name.svm_cid != VMADDR_CID_ANY || name.svm_port != 15555) die("getsockname, bound", name.svm_cid, name.svm_port);
    if (bind_to(s, VMADDR_CID_ANY, 15556) == 0 || errno != EINVAL) die("bind, bound", 0, errno);
    int t = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (bind_to(t, VMADDR_CID_ANY, 15555) == 0 || errno != EADDRINUSE) die("bind, a port in use", 0, errno);
    if (listen(s, 4) || listen(s, 8)) die("listen", 0, errno);
    struct pollfd p = {s, POLLIN | POLLOUT, 0};
    if (poll(&p, 1, 0) != 0) die("poll, listening", p.revents, 0);
    if (accept4(s, 0, 0, 0x40000000) != -1 || errno != EINVAL) die("accept4, unknown flags", 0, errno);
    if (connect_to(s, VMADDR_CID_HOST, 5000) == 0 || errno != EINVAL) die("connect, listening", 0, errno);
    len = sizeof name;
    if (getpeername(s, (struct sockaddr *)&name, &len) == 0 || errno != ENOTCONN) die("getpeername, listening", 0, errno);
    if (shutdown(s, SHUT_RDWR) == 0 || errno != ENOTCONN) die("shutdown, listening", 0, errno);
    char c;
    if (read(s, &c, 1) != -1 || errno != ENOTCONN) die("read, listening", 0, errno);
    if (write(s, "x", 1) != -1 || errno != ENOTCONN) die("write, listening", 0, errno);
    // An accept that waits, waits.
    child = fork();
    if (child == 0) {
        accept(s, 0, 0);
        _exit(3);
    }
    sleep_ms(300);
    if (waitpid(child, &status, WNOHANG) != 0) die("accept did not wait", status, 0);
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    fcntl(s, F_SETFL, O_NONBLOCK);
    if (accept(s, 0, 0) != -1 || errno != EAGAIN) die("accept, not waiting", 0, errno);
    close(s);
    if (bind_to(t, VMADDR_CID_ANY, 15555)) die("bind, a port let go", 0, errno);
    close(t);
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
    if (bind_to(fd, VMADDR_CID_ANY, VMADDR_PORT_ANY) == 0 || errno != EINVAL) die("bind, bound by connect", 0, errno);
    if (listen(fd, 1)) die("listen, bound by connect", 0, errno);
    close(fd);

    listener();

    // The emulator's services, if this host is the emulator.
    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (connect_to(fd, VMADDR_CID_HOST, 5000)) {
        if (errno != ECONNRESET) die("connect to port 5000", 0, errno);
        printf("vsock: no emulator at port 5000\n");
    } else {
        len = sizeof name;
        if (getpeername(fd, (struct sockaddr *)&name, &len) || name.svm_cid != VMADDR_CID_HOST || name.svm_port != 5000) die("getpeername", name.svm_cid, name.svm_port);
        if (connect_to(fd, VMADDR_CID_HOST, 5000) == 0 || errno != EISCONN) die("connect, connected", 0, errno);
        if (listen(fd, 1) == 0 || errno != EINVAL) die("listen, connected", 0, errno);
        if (accept(fd, 0, 0) != -1 || errno != EINVAL) die("accept, connected", 0, errno);
        static const char hello[] = "pipe:qemud:sensors";
        if (write(fd, hello, sizeof hello) != sizeof hello) die("the connection string", 0, errno);
        if (write(fd, "000clist-sensors", 16) != 16) die("list-sensors", 0, errno);
        if (read_fully(fd, buf, 4) || memcmp(buf, "0001", 4) || read_fully(fd, buf, 1) || buf[0] != '0') die("the sensors' mask", buf[0], 0);
        printf("vsock: the emulator's sensors service says there are none\n");
        if (shutdown(fd, SHUT_WR)) die("shutdown", 0, errno);
        if (read(fd, buf, sizeof buf) != 0) die("read after shutdown", 0, errno);
        if (write(fd, "x", 1) != -1 || errno != EPIPE) die("write after shutdown", 0, errno);
        close(fd);

        fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        static const char props[] = "pipe:qemud:boot-properties";
        if (connect_to(fd, VMADDR_CID_HOST, 5000) || write(fd, props, sizeof props) != sizeof props || write(fd, "0004list", 8) != 8) die("boot-properties", 0, errno);
        if (read_fully(fd, buf, 5) || memcmp(buf, "0001", 5)) die("the end of the properties", buf[4], 0);
        close(fd);

        fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        static const char misc[] = "pipe:QemuMiscPipe";
        if (connect_to(fd, VMADDR_CID_HOST, 5000) || write(fd, misc, sizeof misc) != sizeof misc) die("the misc pipe", 0, errno);
        static const char *const asks[] = {"heartbeat", "get_random=12", "what"};
        static const int answers[] = {3, 12, 3};
        for (int i = 0; i < 3; i++) {
            int32_t n = strlen(asks[i]) + 1, got;
            if (write(fd, &n, 4) != 4 || write(fd, asks[i], n) != n) die("a misc message", i, errno);
            if (read_fully(fd, (char *)&got, 4) || got != answers[i] || read_fully(fd, buf, got)) die("a misc answer", i, got);
            if (i == 0 && memcmp(buf, "OK", 3)) die("a heartbeat's answer", buf[0], 0);
            if (i == 2 && memcmp(buf, "KO", 3)) die("an unknown message's answer", buf[0], 0);
        }
        printf("vsock: no boot properties, and the misc pipe answers\n");
    }
    close(fd);
    printf("vsock ok\n");
    return 0;
}
