// AF_UNIX SOCK_SEQPACKET: a connection of records. Android's logd serves
// its readers on one (logdr), and logcat reads one log entry a read; lmkd
// and tombstoned take their requests the same way.
//
// - each send is one record and each read takes one, however short its
//   buffer: the rest of a record that does not fit is dropped, MSG_TRUNC
//   set in msg_flags, and with MSG_TRUNC asked the whole length returned;
// - a record of no bytes is read as one (0), and polls readable;
// - a peek leaves the record; a read with no room takes it all the same;
// - a record longer than the send buffer allows is EMSGSIZE, the longest
//   that fits goes whole;
// - a writev is one record, however long;
// - descriptors go with their record;
// - a listener's connections are records too; a stream socket connecting
//   to it is refused (an abstract name) or EPROTOTYPE (a path);
// - the writer gone, a read is end of file.
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

static void fail(const char *what, long got, long want) {
    printf("seqpacket: %s: got %ld (errno %d), wanted %ld\n", what, got, errno, want);
    exit(1);
}

static void expect(const char *what, long got, long want) {
    if (got != want) fail(what, got, want);
}

static long rd(int fd, void *buf, size_t len, int flags) {
    long n = recv(fd, buf, len, flags);
    return n < 0 ? -errno : n;
}

static long snd(int fd, const void *buf, size_t len) {
    long n = send(fd, buf, len, MSG_NOSIGNAL);
    return n < 0 ? -errno : n;
}

int main(void) {
    int sv[2];
    char buf[64];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, sv)) fail("socketpair", -errno, 0);

    // Boundaries, and a record of nothing.
    expect("send abc", snd(sv[0], "abc", 3), 3);
    expect("send nothing", snd(sv[0], "", 0), 0);
    expect("send defgh", snd(sv[0], "defgh", 5), 5);
    expect("read abc", rd(sv[1], buf, sizeof buf, 0), 3);
    struct pollfd p = {sv[1], POLLIN, 0};
    expect("poll with a record of nothing", poll(&p, 1, 0), 1);
    expect("read nothing", rd(sv[1], buf, sizeof buf, 0), 0);
    expect("read defgh", rd(sv[1], buf, sizeof buf, 0), 5);
    expect("defgh", memcmp(buf, "defgh", 5), 0);
    expect("read with none", rd(sv[1], buf, sizeof buf, 0), -EAGAIN);

    // Truncation.
    expect("send ten", snd(sv[0], "0123456789", 10), 10);
    expect("send AB", snd(sv[0], "AB", 2), 2);
    struct iovec iov = {buf, 4};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    expect("recvmsg four of ten", recvmsg(sv[1], &msg, 0), 4);
    expect("MSG_TRUNC set", !!(msg.msg_flags & MSG_TRUNC), 1);
    expect("0123", memcmp(buf, "0123", 4), 0);
    expect("the next record", rd(sv[1], buf, sizeof buf, 0), 2);
    expect("send ten", snd(sv[0], "0123456789", 10), 10);
    expect("recv four with MSG_TRUNC", rd(sv[1], buf, 4, MSG_TRUNC), 10);
    expect("nothing left of it", rd(sv[1], buf, sizeof buf, 0), -EAGAIN);

    // A peek, and a read with no room.
    expect("send xyz", snd(sv[0], "xyz", 3), 3);
    expect("peek", rd(sv[1], buf, sizeof buf, MSG_PEEK), 3);
    expect("peek again, short", rd(sv[1], buf, 2, MSG_PEEK), 2);
    expect("read after the peeks", rd(sv[1], buf, sizeof buf, 0), 3);
    expect("send q", snd(sv[0], "q", 1), 1);
    iov.iov_len = 0;
    msg.msg_flags = 0;
    expect("recvmsg with no room", recvmsg(sv[1], &msg, 0), 0);
    expect("MSG_TRUNC set", !!(msg.msg_flags & MSG_TRUNC), 1);
    expect("the record taken", rd(sv[1], buf, sizeof buf, 0), -EAGAIN);

    // The longest record.
    size_t big = 212992 - 32;
    char *large = calloc(1, big + 1);
    expect("one byte too long", snd(sv[0], large, big + 1), -EMSGSIZE);
    expect("the longest", snd(sv[0], large, big), (long)big);
    expect("read the longest", rd(sv[1], large, big + 1, 0), (long)big);

    // A writev is one record, however long.
    struct iovec two[2] = {{large, 1000}, {large + 1000, 5000}};
    expect("writev of 6000 in two", writev(sv[0], two, 2), 6000);
    expect("read it as one", rd(sv[1], large, big, 0), 6000);

    // Descriptors with their record.
    int pfd[2];
    if (pipe(pfd)) fail("pipe", -errno, 0);
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof cbuf);
    struct msghdr out = {0};
    struct iovec oi = {"with", 4};
    out.msg_iov = &oi;
    out.msg_iovlen = 1;
    out.msg_control = cbuf;
    out.msg_controllen = sizeof cbuf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&out);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &pfd[1], sizeof(int));
    expect("sendmsg with a descriptor", sendmsg(sv[0], &out, 0), 4);
    expect("send without", snd(sv[0], "without", 7), 7);
    char rbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr in = {0};
    iov.iov_base = buf;
    iov.iov_len = 2;
    in.msg_iov = &iov;
    in.msg_iovlen = 1;
    in.msg_control = rbuf;
    in.msg_controllen = sizeof rbuf;
    expect("recvmsg two of the record with it", recvmsg(sv[1], &in, 0), 2);
    expect("its descriptor", in.msg_controllen > 0 && CMSG_FIRSTHDR(&in) && CMSG_FIRSTHDR(&in)->cmsg_type == SCM_RIGHTS, 1);
    in.msg_controllen = sizeof rbuf;
    iov.iov_len = sizeof buf;
    expect("recvmsg the record without", recvmsg(sv[1], &in, 0), 7);
    expect("no descriptor", in.msg_controllen, 0);

    // End of file.
    close(sv[0]);
    expect("read after the writer went", rd(sv[1], buf, sizeof buf, 0), 0);
    close(sv[1]);

    // A listener.
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path + 1, sizeof addr.sun_path - 1, "gex-seqpacket-%d", getpid());
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr.sun_path + 1);
    int l = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (l < 0 || bind(l, (struct sockaddr *)&addr, alen) || listen(l, 4)) fail("listener", -errno, 0);
    // Another type: an abstract name of it is not found, a path's is
    // EPROTOTYPE.
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    expect("a stream socket connecting to the abstract name", connect(s, (struct sockaddr *)&addr, alen) ? -errno : 0, -ECONNREFUSED);
    close(s);
    struct sockaddr_un named = {.sun_family = AF_UNIX};
    snprintf(named.sun_path, sizeof named.sun_path, "/tmp/gex-seqpacket-%d", getpid());
    unlink(named.sun_path);
    int pl = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (pl < 0 || bind(pl, (struct sockaddr *)&named, sizeof named) || listen(pl, 1)) fail("a listener at a path", -errno, 0);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    expect("a stream socket connecting to the path", connect(s, (struct sockaddr *)&named, sizeof named) ? -errno : 0, -EPROTOTYPE);
    close(s);
    close(pl);
    unlink(named.sun_path);
    int cl = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    expect("connect", connect(cl, (struct sockaddr *)&addr, alen) ? -errno : 0, 0);
    int ac = accept(l, NULL, NULL);
    if (ac < 0) fail("accept", -errno, 0);
    expect("send one", snd(cl, "one", 3), 3);
    expect("send two", snd(cl, "two", 3), 3);
    expect("read one", rd(ac, buf, sizeof buf, 0), 3);
    expect("read two", rd(ac, buf, sizeof buf, 0), 3);
    int type = 0;
    socklen_t tl = sizeof type;
    getsockopt(ac, SOL_SOCKET, SO_TYPE, &type, &tl);
    expect("the accepted socket's type", type, SOCK_SEQPACKET);

    printf("seqpacket ok\n");
    return 0;
}
