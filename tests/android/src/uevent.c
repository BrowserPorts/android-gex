// The netlink socket device events come over (NETLINK_KOBJECT_UEVENT):
// what Android's ueventd opens before anything else, and udev's monitor.
//
// - It is a socket: of family AF_NETLINK, the type it was asked as, its
//   protocol; a stream one is ESOCKTNOSUPPORT and a protocol nobody has
//   EPROTONOSUPPORT.
// - Its receive buffer is twice what SO_RCVBUF asks, what was asked being
//   no more than net.core.rmem_max; SO_RCVBUFFORCE passes that limit, for
//   one with CAP_NET_ADMIN. ueventd asks, reads back, and forces.
// - Before it is bound its name is port 0, no groups. Bound with port 0
//   it gets the process's id; a second socket of the process, some
//   negative number; a port another socket has is EADDRINUSE, and a
//   bound socket binds again only to its own port (EINVAL). Anyone may
//   listen to its groups.
// - With nothing sent a receive is EAGAIN and poll does not say readable.
// - A process with CAP_SYS_ADMIN can have the kernel broadcast a uevent:
//   a netlink message whose payload goes to group 1 from port 0, with
//   "SEQNUM=<n>" added and the sender's credentials. It asks for an
//   acknowledgement and gets one: NLMSG_ERROR with 0 and its header.
// - One without it is told EPERM, its request returned whole; and may not
//   send to another socket or to a group at all (EPERM from the send).
// - MSG_PEEK leaves a datagram; MSG_TRUNC returns its whole length when
//   the buffer was shorter, and what did not fit is gone.
// - net.core.rmem_max can be set, and is the limit from then.
// - A listener that falls behind loses events and is told once (ENOBUFS),
//   then reads what it has: as many as the kernel counts its buffer to
//   hold.
//
// Other events arrive on a real kernel while this runs, so the test's are
// known by an action of their own ("gextest") and a name that carries this
// process's number.
//
// Needs root (to force a buffer, and to broadcast); otherwise the program
// says so and exits 77.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif

static char tag[64];

static void die(const char *what, long a, long b) {
    printf("uevent: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

static int sysctl(const char *name) {
    char path[128], text[32] = {0};
    snprintf(path, sizeof path, "/proc/sys/net/core/%s", name);
    int fd = open(path, O_RDONLY);
    if (fd < 0 || read(fd, text, sizeof text - 1) <= 0) die(path, fd, 0);
    close(fd);
    return atoi(text);
}

// Set a limit under /proc/sys/net/core: 0, or the errno.
static int set_sysctl(const char *name, const char *text) {
    char path[128];
    snprintf(path, sizeof path, "/proc/sys/net/core/%s", name);
    int fd = open(path, O_WRONLY);
    if (fd < 0) die(path, fd, 1);
    int e = write(fd, text, strlen(text)) == (ssize_t)strlen(text) ? 0 : errno;
    close(fd);
    return e;
}

static int uevent_socket(void) {
    int s = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    if (s < 0) die("socket", s, 0);
    return s;
}

static struct sockaddr_nl name_of(int s) {
    struct sockaddr_nl a;
    socklen_t len = sizeof a;
    memset(&a, 0xff, sizeof a);
    if (getsockname(s, (struct sockaddr *)&a, &len) || len != sizeof a || a.nl_family != AF_NETLINK) die("getsockname", len, a.nl_family);
    return a;
}

static int bind_to(int s, uint32_t pid, uint32_t groups) {
    struct sockaddr_nl a = {.nl_family = AF_NETLINK, .nl_pid = pid, .nl_groups = groups};
    return bind(s, (struct sockaddr *)&a, sizeof a) ? errno : 0;
}

static int getint(int s, int level, int name) {
    int v = -1;
    socklen_t len = sizeof v;
    if (getsockopt(s, level, name, &v, &len) || len != sizeof v) die("getsockopt", name, len);
    return v;
}

// A request for the kernel to broadcast `text` (with its NUL) as a uevent.
static size_t request(char *buf, const char *text, uint32_t seq, int ack) {
    struct nlmsghdr h = {.nlmsg_len = NLMSG_HDRLEN + strlen(text) + 1, .nlmsg_type = NLMSG_MIN_TYPE, .nlmsg_flags = NLM_F_REQUEST | (ack ? NLM_F_ACK : 0), .nlmsg_seq = seq};
    memcpy(buf, &h, sizeof h);
    memcpy(buf + NLMSG_HDRLEN, text, strlen(text) + 1);
    return h.nlmsg_len;
}

// What a receive gave: the datagram, where it came from, whose it was.
struct got {
    char data[4096];
    ssize_t len;
    struct sockaddr_nl from;
    int flags;
    int has_cred;
    struct ucred cred;
};

static int receive(int s, struct got *g, size_t room, int flags) {
    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec iov = {g->data, room};
    struct msghdr m = {.msg_name = &g->from, .msg_namelen = sizeof g->from, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control};
    memset(&g->from, 0xff, sizeof g->from);
    g->len = recvmsg(s, &m, flags);
    if (g->len < 0) return errno;
    g->flags = m.msg_flags;
    g->has_cred = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS) {
            memcpy(&g->cred, CMSG_DATA(c), sizeof g->cred);
            g->has_cred = 1;
        }
    }
    if (m.msg_namelen != sizeof g->from) die("a sender's name", m.msg_namelen, 0);
    return 0;
}

// The next datagram that is one of this test's, waiting a while for it.
static void mine(int s, struct got *g, size_t room, int flags) {
    for (int tries = 0; tries < 200; tries++) {
        struct pollfd p = {s, POLLIN, 0};
        if (poll(&p, 1, 50) < 0) die("poll", 0, 0);
        if (!(p.revents & POLLIN)) continue;
        int e = receive(s, g, room, flags);
        if (e == EAGAIN) continue;
        if (e) die("recvmsg", e, 0);
        size_t n = (size_t)g->len < room ? (size_t)g->len : room;
        if (n >= 8 && !memcmp(g->data, "gextest@", 8)) return;
    }
    die("no event of this test's arrived", 0, 0);
}

// `count` events of `text` asked of the kernel through `from` while
// nobody reads `to`: how many `to` kept, after being told it lost some.
static int flood_kept;
static int flood(int from, int to, const char *text, int count) {
    char buf[2048];
    struct got g;
    size_t len = request(buf, text, 50, 0);
    for (int i = 0; i < count; i++) {
        if (send(from, buf, len, 0) != (ssize_t)len) die("a flood", errno, i);
    }
    int e = receive(to, &g, sizeof g.data, 0);
    if (e != ENOBUFS) die("what a listener that fell behind is told", e, 0);
    flood_kept = 0;
    while ((e = receive(to, &g, sizeof g.data, 0)) == 0) {
        if (g.len >= 8 && !memcmp(g.data, "gextest@", 8)) flood_kept++;
    }
    if (e != EAGAIN) die("the end of what it kept", e, 0);
    return flood_kept;
}

// What a process that is not root may and may not do, in a child.
static void unprivileged(uint32_t listener) {
    pid_t child = fork();
    if (child < 0) die("fork", 0, 0);
    if (child == 0) {
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) die("dropping root", 0, 0);
        int s = uevent_socket();
        // It may listen.
        if (bind_to(s, 0, 1)) die("an ordinary process's bind to the group", errno, 0);
        if (bind_to(s, getpid(), 0) || name_of(s).nl_groups != 0) die("leaving the group", errno, 0);
        int big = 64 << 20;
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &big, sizeof big) == 0 || errno != EPERM) die("forcing a buffer without the right", errno, 0);
        // Not send to another socket, or to the group.
        struct sockaddr_nl to = {.nl_family = AF_NETLINK, .nl_pid = listener};
        if (sendto(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to) >= 0 || errno != EPERM) die("an ordinary send to a socket", errno, 0);
        to.nl_pid = 0;
        to.nl_groups = 1;
        if (sendto(s, "x", 1, 0, (struct sockaddr *)&to, sizeof to) >= 0 || errno != EPERM) die("an ordinary send to the group", errno, 0);
        if (connect(s, (struct sockaddr *)&to, sizeof to) == 0 || errno != EPERM) die("an ordinary connect to the group", errno, 0);
        // Its request to broadcast goes to the kernel, which refuses it
        // and sends the request back whole.
        char buf[256], text[128];
        snprintf(text, sizeof text, "gextest@/devices/%s-refused", tag);
        size_t len = request(buf, text, 7, 0);
        if (send(s, buf, len, 0) != (ssize_t)len) die("an ordinary request", errno, 0);
        struct got g;
        int e = receive(s, &g, sizeof g.data, 0);
        if (e) die("the refusal", e, 0);
        struct nlmsghdr h;
        struct nlmsgerr err;
        memcpy(&h, g.data, sizeof h);
        memcpy(&err, g.data + NLMSG_HDRLEN, sizeof err);
        if (h.nlmsg_type != NLMSG_ERROR || h.nlmsg_seq != 7 || h.nlmsg_pid != name_of(s).nl_pid || err.error != -EPERM) die("the refusal's message", h.nlmsg_type, err.error);
        if ((size_t)g.len != NLMSG_HDRLEN + sizeof(int) + NLMSG_ALIGN(len) || h.nlmsg_len != (size_t)g.len || (h.nlmsg_flags & NLM_F_CAPPED)) die("the refusal's length", g.len, h.nlmsg_flags);
        if (memcmp(g.data + NLMSG_HDRLEN + sizeof(int), buf, len)) die("the request in the refusal", 0, 0);
        if (g.from.nl_pid != 0 || g.from.nl_groups != 0) die("the refusal's sender", g.from.nl_pid, g.from.nl_groups);
        // With NETLINK_CAP_ACK, only its header.
        int on = 1;
        if (setsockopt(s, SOL_NETLINK, NETLINK_CAP_ACK, &on, sizeof on)) die("NETLINK_CAP_ACK", errno, 0);
        if (send(s, buf, len, 0) != (ssize_t)len) die("an ordinary request", errno, 1);
        e = receive(s, &g, sizeof g.data, 0);
        memcpy(&h, g.data, sizeof h);
        if (e || g.len != NLMSG_HDRLEN + sizeof(struct nlmsgerr) || !(h.nlmsg_flags & NLM_F_CAPPED)) die("a capped refusal", g.len, h.nlmsg_flags);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) die("the unprivileged child", status, 0);
}

int main(void) {
    if (geteuid() != 0) {
        printf("uevent: needs root\n");
        return 77;
    }
    snprintf(tag, sizeof tag, "gex-uevent-test-%d", getpid());
    int rmem_max = sysctl("rmem_max"), rmem_default = sysctl("rmem_default");

    // A socket, and what it says it is.
    int s = uevent_socket();
    if (getint(s, SOL_SOCKET, SO_TYPE) != SOCK_DGRAM || getint(s, SOL_SOCKET, SO_DOMAIN) != AF_NETLINK || getint(s, SOL_SOCKET, SO_PROTOCOL) != NETLINK_KOBJECT_UEVENT) die("what the socket is", getint(s, SOL_SOCKET, SO_TYPE), getint(s, SOL_SOCKET, SO_PROTOCOL));
    int raw = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (raw < 0 || getint(raw, SOL_SOCKET, SO_TYPE) != SOCK_RAW) die("a raw socket", raw, 0);
    close(raw);
    if (socket(AF_NETLINK, SOCK_STREAM, NETLINK_KOBJECT_UEVENT) >= 0 || errno != ESOCKTNOSUPPORT) die("a stream socket", errno, 0);
    if (socket(AF_NETLINK, SOCK_DGRAM, 17) >= 0 || errno != EPROTONOSUPPORT) die("a protocol nobody has", errno, 0);

    // Its receive buffer, as ueventd sets it.
    if (getint(s, SOL_SOCKET, SO_RCVBUF) != rmem_default) die("the buffer a socket starts with", getint(s, SOL_SOCKET, SO_RCVBUF), rmem_default);
    int want = 16 << 20;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &want, sizeof want)) die("SO_RCVBUF", errno, 0);
    int expect = 2 * (want < rmem_max ? want : rmem_max);
    if (getint(s, SOL_SOCKET, SO_RCVBUF) != expect) die("SO_RCVBUF read back", getint(s, SOL_SOCKET, SO_RCVBUF), expect);
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &want, sizeof want)) die("SO_RCVBUFFORCE", errno, 0);
    if (getint(s, SOL_SOCKET, SO_RCVBUF) != 2 * want) die("SO_RCVBUFFORCE read back", getint(s, SOL_SOCKET, SO_RCVBUF), 2 * want);
    int tiny = 1;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &tiny, sizeof tiny)) die("SO_RCVBUF", errno, 1);
    int least = getint(s, SOL_SOCKET, SO_RCVBUF);
    if (least != 2304) die("the least a receive buffer is", least, 0);
    int on = 1;
    if (getint(s, SOL_SOCKET, SO_PASSCRED) != 0) die("SO_PASSCRED before it is set", 0, 0);
    if (setsockopt(s, SOL_SOCKET, SO_PASSCRED, &on, sizeof on) || getint(s, SOL_SOCKET, SO_PASSCRED) != 1) die("SO_PASSCRED", errno, 0);

    // Its name, before and after it is bound.
    struct sockaddr_nl a = name_of(s);
    if (a.nl_pid != 0 || a.nl_groups != 0) die("an unbound socket's name", a.nl_pid, a.nl_groups);
    struct sockaddr_un_like {
        sa_family_t family;
        char pad[14];
    } wrong = {AF_UNIX, {0}};
    if (bind(s, (struct sockaddr *)&wrong, sizeof wrong) == 0 || errno != EINVAL) die("a bind to another family's address", errno, 0);
    struct sockaddr_nl ok = {.nl_family = AF_NETLINK};
    if (bind(s, (struct sockaddr *)&ok, sizeof ok - 1) == 0 || errno != EINVAL) die("a bind to an address too short", errno, 0);
    if (bind_to(s, 0, 0xffffffff)) die("bind", errno, 0);
    a = name_of(s);
    if (a.nl_pid != (uint32_t)getpid() || a.nl_groups != 0xffffffff) die("a bound socket's name", a.nl_pid, a.nl_groups);
    socklen_t plen = sizeof a;
    memset(&a, 0xff, sizeof a);
    if (getpeername(s, (struct sockaddr *)&a, &plen) || plen != sizeof a || a.nl_family != AF_NETLINK || a.nl_pid != 0 || a.nl_groups != 0) die("its peer's name", a.nl_pid, a.nl_groups);
    if (bind_to(s, 0, 1) != EINVAL) die("a bound socket bound to port 0", errno, 0);
    if (bind_to(s, getpid(), 1)) die("a bound socket bound to its own port", errno, 0);
    if (name_of(s).nl_groups != 1) die("its groups after that", name_of(s).nl_groups, 0);
    int second = uevent_socket();
    if (bind_to(second, getpid(), 0) != EADDRINUSE) die("a port another socket has", errno, 0);
    if (bind_to(second, 0, 0)) die("a second socket's bind", errno, 0);
    int32_t port = (int32_t)name_of(second).nl_pid;
    if (port > -4097) die("a second socket's port", port, 0);
    // A route socket's ports are another protocol's: the process's id again.
    int route = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (route < 0 || bind_to(route, 0, 0) || name_of(route).nl_pid != (uint32_t)getpid()) die("a route socket's port", route, errno);
    close(route);
    // Groups, one at a time.
    int group = 1;
    if (setsockopt(second, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof group) || name_of(second).nl_groups != 1) die("NETLINK_ADD_MEMBERSHIP", errno, name_of(second).nl_groups);
    if (setsockopt(second, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, &group, sizeof group) || name_of(second).nl_groups != 0) die("NETLINK_DROP_MEMBERSHIP", errno, name_of(second).nl_groups);
    group = 0;
    if (setsockopt(second, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof group) == 0 || errno != EINVAL) die("group 0", errno, 0);
    group = 33;
    if (setsockopt(second, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof group) == 0 || errno != EINVAL) die("group 33", errno, 0);

    // Nothing sent to the second socket: nothing to read.
    struct got g;
    struct pollfd p = {second, POLLIN | POLLOUT, 0};
    if (poll(&p, 1, 0) != 1 || p.revents != POLLOUT) die("poll of a socket with nothing", p.revents, 0);
    if (receive(second, &g, sizeof g.data, 0) != EAGAIN) die("a receive with nothing", errno, 0);
    char one;
    if (read(second, &one, 1) >= 0 || errno != EAGAIN) die("a read with nothing", errno, 0);
    if (send(second, "", 0, 0) >= 0 || errno != ENODATA) die("an empty send", errno, 0);

    // A broadcast, asked of the kernel by the second socket and heard by
    // the first; the asker is told it was done.
    int big = 1 << 20;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &big, sizeof big)) die("SO_RCVBUFFORCE", errno, 1);
    char buf[2048], text[256];
    snprintf(text, sizeof text, "gextest@/devices/%s", tag);
    size_t len = request(buf, text, 41, 1);
    if (send(second, buf, len, 0) != (ssize_t)len) die("the request to broadcast", errno, 0);
    mine(s, &g, sizeof g.data, MSG_PEEK);
    ssize_t peeked = g.len;
    mine(s, &g, sizeof g.data, 0);
    if (g.len != peeked) die("a datagram after it was peeked at", g.len, peeked);
    size_t tlen = strlen(text) + 1;
    if ((size_t)g.len <= tlen + 7 || memcmp(g.data, text, tlen) || memcmp(g.data + tlen, "SEQNUM=", 7) || g.data[g.len - 1] != 0) die("the event as it arrived", g.len, tlen);
    unsigned long long seq1 = strtoull(g.data + tlen + 7, NULL, 10);
    if ((size_t)g.len != tlen + 7 + strlen(g.data + tlen + 7) + 1 || seq1 == 0) die("the event's sequence number", g.len, seq1);
    if (g.from.nl_pid != 0 || g.from.nl_groups != 1 || g.flags != 0) die("the event's sender", g.from.nl_pid, g.from.nl_groups);
    if (!g.has_cred || g.cred.pid != getpid() || g.cred.uid != 0 || g.cred.gid != 0) die("the event's credentials", g.has_cred, g.cred.pid);
    // The acknowledgement: no error, the header alone.
    if (receive(second, &g, sizeof g.data, 0)) die("the acknowledgement", errno, 0);
    struct nlmsghdr h;
    struct nlmsgerr err;
    memcpy(&h, g.data, sizeof h);
    memcpy(&err, g.data + NLMSG_HDRLEN, sizeof err);
    if (g.len != NLMSG_HDRLEN + sizeof err || h.nlmsg_len != g.len || h.nlmsg_type != NLMSG_ERROR || h.nlmsg_flags != NLM_F_CAPPED || h.nlmsg_seq != 41 || h.nlmsg_pid != (uint32_t)port) die("the acknowledgement's header", g.len, h.nlmsg_flags);
    if (err.error != 0 || err.msg.nlmsg_len != len || err.msg.nlmsg_seq != 41) die("the acknowledgement", err.error, err.msg.nlmsg_len);
    if (g.from.nl_pid != 0 || g.from.nl_groups != 0 || g.has_cred) die("the acknowledgement's sender", g.from.nl_pid, g.has_cred);
    // The second socket was not listening, and heard nothing.
    if (receive(second, &g, sizeof g.data, 0) != EAGAIN) die("an event on a socket not listening", g.len, 0);

    // The next event's number is the next; into a short buffer it is cut,
    // and said to be, and the rest of it is gone.
    len = request(buf, text, 42, 0);
    if (send(second, buf, len, 0) != (ssize_t)len) die("the request to broadcast", errno, 1);
    mine(s, &g, 10, MSG_TRUNC);
    if ((size_t)g.len <= tlen + 7) die("a cut event's whole length", g.len, 0);
    if (!(g.flags & MSG_TRUNC) || memcmp(g.data, text, 10)) die("a cut event", g.flags, 0);
    len = request(buf, text, 43, 0);
    if (send(second, buf, len, 0) != (ssize_t)len) die("the request to broadcast", errno, 2);
    mine(s, &g, sizeof g.data, 0);
    unsigned long long seq3 = strtoull(g.data + tlen + 7, NULL, 10);
    if (seq3 < seq1 + 2) die("sequence numbers going up", seq1, seq3);
    // Too long with its number: refused, and the asker told.
    char huge[2040];
    memset(huge, 'b', sizeof huge);
    memcpy(huge, text, strlen(text));
    huge[sizeof huge - 1] = 0;
    char hbuf[4096];
    len = request(hbuf, huge, 44, 0);
    if (send(second, hbuf, len, 0) != (ssize_t)len) die("a request too long", errno, 0);
    if (receive(second, &g, sizeof g.data, 0)) die("the answer to a request too long", errno, 0);
    memcpy(&err, g.data + NLMSG_HDRLEN, sizeof err);
    if (err.error != -EINVAL) die("a request too long", err.error, 0);

    // One socket to another, by its port: root's to do.
    struct sockaddr_nl to = {.nl_family = AF_NETLINK, .nl_pid = (uint32_t)getpid()};
    if (sendto(second, "hello", 5, 0, (struct sockaddr *)&to, sizeof to) != 5) die("a send to a socket", errno, 0);
    if (receive(s, &g, sizeof g.data, 0) || g.len != 5 || memcmp(g.data, "hello", 5)) die("what was sent to a socket", g.len, 0);
    if (g.from.nl_pid != (uint32_t)port || g.from.nl_groups != 0 || !g.has_cred || g.cred.pid != getpid()) die("its sender", g.from.nl_pid, g.from.nl_groups);
    to.nl_pid = 0x7fffff00;
    if (sendto(second, "hello", 5, 0, (struct sockaddr *)&to, sizeof to) >= 0 || errno != ECONNREFUSED) die("a send to a port nobody has", errno, 0);

    unprivileged((uint32_t)getpid());

    // A listener that falls behind: events are lost, and it is told so
    // once, before the ones it has. How many it has room for is the
    // kernel's reckoning of what a datagram costs (the whole allocation
    // behind it): with the least buffer two short ones, the first because
    // the queue was empty; with the buffer a socket starts with, 166 of
    // 600 bytes.
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &tiny, sizeof tiny)) die("SO_RCVBUF", errno, 2);
    snprintf(text, sizeof text, "gextest@/devices/%s-flood", tag);
    if (flood(second, s, text, 64) != 2) die("what a flooded listener with the least buffer kept", flood_kept, 0);
    int usual = rmem_default / 2;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &usual, sizeof usual) || getint(s, SOL_SOCKET, SO_RCVBUF) != rmem_default) die("SO_RCVBUF", errno, 3);
    char longer[560];
    memset(longer, 'c', sizeof longer);
    memcpy(longer, text, strlen(text));
    longer[sizeof longer - 1] = 0;
    if (flood(second, s, longer, 200) != 166) die("what a flooded listener kept of longer events", flood_kept, 0);
    // Having read it all, it hears again.
    len = request(buf, text, 60, 0);
    if (send(second, buf, len, 0) != (ssize_t)len) die("a request after the flood", errno, 0);
    mine(s, &g, sizeof g.data, 0);

    // The limit moved, as Android's init moves it (init.rc writes 262144
    // to rmem_max and wmem_max): what a socket may ask for follows. A
    // limit below the least a buffer may be, or not a number, is EINVAL.
    char was[32];
    snprintf(was, sizeof was, "%d\n", rmem_max);
    if (set_sysctl("rmem_max", "262144\n")) die("setting rmem_max", errno, 0);
    if (sysctl("rmem_max") != 262144) die("rmem_max after it was set", sysctl("rmem_max"), 0);
    int third = uevent_socket();
    if (setsockopt(third, SOL_SOCKET, SO_RCVBUF, &want, sizeof want) || getint(third, SOL_SOCKET, SO_RCVBUF) != 2 * 262144) die("a buffer under the new limit", getint(third, SOL_SOCKET, SO_RCVBUF), 0);
    close(third);
    if (set_sysctl("rmem_max", "1") != EINVAL || set_sysctl("rmem_max", "many") != EINVAL || sysctl("rmem_max") != 262144) die("what is not a limit", errno, sysctl("rmem_max"));
    if (set_sysctl("rmem_max", was) || sysctl("rmem_max") != rmem_max) die("putting rmem_max back", errno, 0);

    printf("uevent ok\n");
    return 0;
}
