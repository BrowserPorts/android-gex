// NETLINK_SOCK_DIAG as Android's netd and system server use it, over this
// program's own sockets (a loopback TCP listener and connection, a bound
// UDP socket), found by their cookies (SO_COOKIE) since a dump's order is
// the kernel's own:
//
// - dumps by family, protocol and states: the listener (state 10) only
//   when LISTEN is asked for, the connection's two ends (1), the UDP
//   socket (7); each entry's ports, addresses, uid, inode (fstat's) and,
//   for root, its mark (SO_MARK); INET_DIAG_INFO when asked for (280
//   bytes, state first); an IPv4 socket not in an IPv6 dump;
// - netd's source-address program (INET_DIAG_BC_S_COND) taking only the
//   sockets on that address and port;
// - exact lookups: TCP by (local, remote), UDP by (remote, local), a
//   wrong cookie ENOENT for TCP and ESTALE for UDP, a socket not there
//   ENOENT;
// - refusals: a family with no handler ENOENT, a short request EINVAL,
//   type 19 EINVAL, a bad program EINVAL, an unknown protocol's dump a
//   DONE carrying -ENOENT;
// - SOCK_DESTROY: a TCP end gets ECONNABORTED once, then end of file and
//   EPIPE, POLLERR|POLLHUP; again ENOENT; a destroyed listener's accept
//   EINVAL; a UDP socket ECONNABORTED before anything, then nothing;
// - a UDP socket let go is told to group 2 with its cookie (96 bytes).
//
// As root. Prints nothing when all is as the source says.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("sockdiag: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static unsigned char buf[65536];

struct req {
    struct nlmsghdr h;
    struct inet_diag_req_v2 r;
    unsigned char bc[64];
};

// Send a request; for an error ack, its error; else the bytes of the first
// datagram.
static long send_req(int fd, uint16_t type, uint16_t flags, uint8_t family, uint8_t proto, uint8_t ext, uint32_t states, const struct inet_diag_sockid *id, const void *bc, int bclen) {
    struct req q;
    memset(&q, 0, sizeof q);
    int len = sizeof q.h + sizeof q.r;
    if (bclen) {
        struct nlattr *a = (struct nlattr *)q.bc;
        a->nla_type = INET_DIAG_REQ_BYTECODE;
        a->nla_len = NLA_HDRLEN + bclen;
        memcpy(a + 1, bc, bclen);
        len += NLA_ALIGN(a->nla_len);
    }
    q.h.nlmsg_len = len;
    q.h.nlmsg_type = type;
    q.h.nlmsg_flags = NLM_F_REQUEST | flags;
    q.h.nlmsg_seq = 5;
    q.r.sdiag_family = family;
    q.r.sdiag_protocol = proto;
    q.r.idiag_ext = ext;
    q.r.idiag_states = states;
    if (id) q.r.id = *id;
    if (send(fd, &q, len, 0) != len) return -errno;
    long n = recv(fd, buf, sizeof buf, 0);
    if (n < 0) return -errno;
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    if (h->nlmsg_type == NLMSG_ERROR) return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
    return n;
}

static uint64_t cookie_of(int fd) {
    uint64_t c = 0;
    socklen_t l = sizeof c;
    getsockopt(fd, SOL_SOCKET, SO_COOKIE, &c, &l);
    return c;
}

static uint64_t msg_cookie(struct inet_diag_msg *m) { return m->id.idiag_cookie[0] | (uint64_t)m->id.idiag_cookie[1] << 32; }

// A dump's entries until DONE: the one with this cookie copied out, how
// many there were, and DONE's status.
struct found {
    int count, done, status, have;
    struct inet_diag_msg msg;
    int mark, has_mark, info_len, info_state;
};

static struct found dump(int fd, uint8_t family, uint8_t proto, uint8_t ext, uint32_t states, uint64_t cookie, const void *bc, int bclen) {
    struct found f;
    memset(&f, 0, sizeof f);
    long n = send_req(fd, SOCK_DIAG_BY_FAMILY, NLM_F_DUMP, family, proto, ext, states, NULL, bc, bclen);
    if (n < 0) {
        f.status = (int)n;
        return f;
    }
    for (int guard = 0; guard < 256 && !f.done; guard++) {
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                f.done = 1;
                f.status = *(int *)NLMSG_DATA(h);
                break;
            }
            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) continue;
            struct inet_diag_msg *m = NLMSG_DATA(h);
            f.count++;
            if (msg_cookie(m) != cookie) continue;
            f.have = 1;
            f.msg = *m;
            int rem = h->nlmsg_len - NLMSG_LENGTH(sizeof *m);
            for (struct rtattr *a = (struct rtattr *)(m + 1); RTA_OK(a, rem); a = RTA_NEXT(a, rem)) {
                if (a->rta_type == INET_DIAG_MARK) {
                    f.has_mark = 1;
                    memcpy(&f.mark, RTA_DATA(a), 4);
                }
                if (a->rta_type == INET_DIAG_INFO) {
                    f.info_len = RTA_PAYLOAD(a);
                    f.info_state = *(unsigned char *)RTA_DATA(a);
                }
            }
        }
        if (!f.done) n = recv(fd, buf, sizeof buf, 0);
    }
    return f;
}

static void check_entry(const char *what, struct found f, int fd, int state, uint16_t sport, uint16_t dport) {
    if (!f.have) {
        printf("sockdiag: %s: not in the dump (%d entries, status %d)\n", what, f.count, f.status);
        failed = 1;
        return;
    }
    struct stat st;
    fstat(fd, &st);
    want(what, f.msg.idiag_state, state);
    want("its source port", ntohs(f.msg.id.idiag_sport), sport);
    want("its destination port", ntohs(f.msg.id.idiag_dport), dport);
    want("its uid", f.msg.idiag_uid, getuid());
    want("its inode", f.msg.idiag_inode, (long)st.st_ino);
    want("its mark", f.has_mark ? f.mark : -1, 77);
}

int main(void) {
    int nl = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (nl < 0) {
        printf("sockdiag: socket: %d\n", errno);
        return 1;
    }
    // A loopback listener and a connection to it, and a bound UDP socket,
    // each marked 77.
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    int lis = socket(AF_INET, SOCK_STREAM, 0), cli = socket(AF_INET, SOCK_STREAM, 0), udp = socket(AF_INET, SOCK_DGRAM, 0);
    int mark = 77;
    setsockopt(lis, SOL_SOCKET, SO_MARK, &mark, 4);
    setsockopt(cli, SOL_SOCKET, SO_MARK, &mark, 4);
    setsockopt(udp, SOL_SOCKET, SO_MARK, &mark, 4);
    want("bind", bind(lis, (struct sockaddr *)&a, sizeof a), 0);
    want("listen", listen(lis, 4), 0);
    getsockname(lis, (struct sockaddr *)&a, &al);
    uint16_t lport = ntohs(a.sin_port);
    want("connect", connect(cli, (struct sockaddr *)&a, sizeof a), 0);
    int srv = accept(lis, NULL, NULL);
    setsockopt(srv, SOL_SOCKET, SO_MARK, &mark, 4);
    struct sockaddr_in c;
    socklen_t cl = sizeof c;
    getsockname(cli, (struct sockaddr *)&c, &cl);
    uint16_t cport = ntohs(c.sin_port);
    struct sockaddr_in u = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    want("udp bind", bind(udp, (struct sockaddr *)&u, sizeof u), 0);
    socklen_t ul = sizeof u;
    getsockname(udp, (struct sockaddr *)&u, &ul);
    uint16_t uport = ntohs(u.sin_port);

    // Dumps.
    uint32_t live = 1 << 1 | 1 << 2 | 1 << 3;
    check_entry("the listener", dump(nl, AF_INET, IPPROTO_TCP, 0, 1 << 10, cookie_of(lis), NULL, 0), lis, 10, lport, 0);
    want("no listener among the live", dump(nl, AF_INET, IPPROTO_TCP, 0, live, cookie_of(lis), NULL, 0).have, 0);
    check_entry("the connecting end", dump(nl, AF_INET, IPPROTO_TCP, 0, live, cookie_of(cli), NULL, 0), cli, 1, cport, lport);
    check_entry("the accepted end", dump(nl, AF_INET, IPPROTO_TCP, 0, live, cookie_of(srv), NULL, 0), srv, 1, lport, cport);
    struct found info = dump(nl, AF_INET, IPPROTO_TCP, 1 << (INET_DIAG_INFO - 1), live, cookie_of(cli), NULL, 0);
    want("tcp_info's length", info.info_len, 280);
    want("tcp_info's state", info.info_state, 1);
    check_entry("the udp socket", dump(nl, AF_INET, IPPROTO_UDP, 0, ~0u, cookie_of(udp), NULL, 0), udp, 7, uport, 0);
    want("not in an IPv6 dump", dump(nl, AF_INET6, IPPROTO_TCP, 0, ~0u, cookie_of(cli), NULL, 0).have, 0);
    struct found unk = dump(nl, AF_INET, 99, 0, ~0u, 0, NULL, 0);
    want("an unknown protocol's dump ends", unk.done, 1);
    want("with -ENOENT", unk.status, -ENOENT);

    // netd's program: sockets whose source is 127.0.0.1 port lport.
    unsigned char bc[20];
    struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)bc;
    op->code = INET_DIAG_BC_S_COND;
    op->yes = 16;
    op->no = 20;
    struct inet_diag_hostcond *hc = (struct inet_diag_hostcond *)(op + 1);
    hc->family = AF_INET;
    hc->prefix_len = 32;
    hc->port = lport;
    uint32_t lo = htonl(INADDR_LOOPBACK);
    memcpy(hc->addr, &lo, 4);
    want("S_COND takes the accepted end", dump(nl, AF_INET, IPPROTO_TCP, 0, live, cookie_of(srv), bc, 16).have, 1);
    want("S_COND leaves the connecting end", dump(nl, AF_INET, IPPROTO_TCP, 0, live, cookie_of(cli), bc, 16).have, 0);
    op->yes = 8;
    want("a bad program", dump(nl, AF_INET, IPPROTO_TCP, 0, live, 0, bc, 16).status, -EINVAL);

    // Exact lookups.
    struct inet_diag_sockid id;
    memset(&id, 0, sizeof id);
    id.idiag_sport = htons(cport);
    id.idiag_dport = htons(lport);
    id.idiag_src[0] = lo;
    id.idiag_dst[0] = lo;
    id.idiag_cookie[0] = id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    long n = send_req(nl, SOCK_DIAG_BY_FAMILY, 0, AF_INET, IPPROTO_TCP, 0, 0, &id, NULL, 0);
    if (n > 0) {
        struct inet_diag_msg *m = NLMSG_DATA((struct nlmsghdr *)buf);
        want("the TCP lookup's socket", msg_cookie(m) == cookie_of(cli), 1);
        want("its flags", ((struct nlmsghdr *)buf)->nlmsg_flags, 0);
    } else {
        want("the TCP lookup", n, 1);
    }
    id.idiag_cookie[0] = (uint32_t)cookie_of(cli) + 1000;
    id.idiag_cookie[1] = 0;
    want("a wrong TCP cookie", send_req(nl, SOCK_DIAG_BY_FAMILY, 0, AF_INET, IPPROTO_TCP, 0, 0, &id, NULL, 0), -ENOENT);
    id.idiag_cookie[0] = id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    id.idiag_sport = htons(1);
    want("no such TCP socket", send_req(nl, SOCK_DIAG_BY_FAMILY, 0, AF_INET, IPPROTO_TCP, 0, 0, &id, NULL, 0), -ENOENT);
    // UDP: src the remote end, dst the local one.
    memset(&id, 0, sizeof id);
    id.idiag_sport = htons(9);
    id.idiag_dport = htons(uport);
    id.idiag_src[0] = lo;
    id.idiag_dst[0] = lo;
    id.idiag_cookie[0] = id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    n = send_req(nl, SOCK_DIAG_BY_FAMILY, 0, AF_INET, IPPROTO_UDP, 0, 0, &id, NULL, 0);
    want("the UDP lookup", n > 0 && msg_cookie(NLMSG_DATA((struct nlmsghdr *)buf)) == cookie_of(udp), 1);
    id.idiag_cookie[0] = (uint32_t)cookie_of(udp) + 1000;
    id.idiag_cookie[1] = 0;
    want("a wrong UDP cookie", send_req(nl, SOCK_DIAG_BY_FAMILY, 0, AF_INET, IPPROTO_UDP, 0, 0, &id, NULL, 0), -ESTALE);

    // Refusals.
    want("no handler for the family", send_req(nl, SOCK_DIAG_BY_FAMILY, NLM_F_DUMP, AF_UNSPEC, IPPROTO_TCP, 0, ~0u, NULL, NULL, 0), -ENOENT);
    want("type 19", send_req(nl, 19, 0, AF_INET, IPPROTO_TCP, 0, ~0u, NULL, NULL, 0), -EINVAL);
    struct {
        struct nlmsghdr h;
        uint8_t family, proto;
    } shortq = {{sizeof shortq, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST, 6, 0}, AF_INET, IPPROTO_TCP};
    want("a short inet request", send(nl, &shortq, sizeof shortq, 0), sizeof shortq);
    n = recv(nl, buf, sizeof buf, 0);
    want("is EINVAL", n > 0 && ((struct nlmsghdr *)buf)->nlmsg_type == NLMSG_ERROR ? ((struct nlmsgerr *)NLMSG_DATA((struct nlmsghdr *)buf))->error : 0, -EINVAL);

    // Destroy the connecting end, with an ack: ECONNABORTED once, then end
    // of file, and EPIPE to a write; POLLERR and POLLHUP before the error
    // is read. A second destroy finds nothing.
    memset(&id, 0, sizeof id);
    id.idiag_sport = htons(cport);
    id.idiag_dport = htons(lport);
    id.idiag_src[0] = lo;
    id.idiag_dst[0] = lo;
    id.idiag_cookie[0] = (uint32_t)cookie_of(cli);
    id.idiag_cookie[1] = (uint32_t)(cookie_of(cli) >> 32);
    want("destroy", send_req(nl, SOCK_DESTROY, NLM_F_ACK, AF_INET, IPPROTO_TCP, 0, 0, &id, NULL, 0), 0);
    struct pollfd pf = {.fd = cli, .events = POLLIN | POLLOUT};
    want("poll after destroy", poll(&pf, 1, 0), 1);
    want("POLLERR and POLLHUP", pf.revents & (POLLERR | POLLHUP), POLLERR | POLLHUP);
    char b1[8];
    want("recv after destroy", recv(cli, b1, sizeof b1, MSG_DONTWAIT) < 0 ? -errno : 0, -ECONNABORTED);
    want("then end of file", recv(cli, b1, sizeof b1, MSG_DONTWAIT), 0);
    want("send after destroy", send(cli, "x", 1, MSG_NOSIGNAL) < 0 ? -errno : 0, -EPIPE);
    want("destroy again", send_req(nl, SOCK_DESTROY, NLM_F_ACK, AF_INET, IPPROTO_TCP, 0, 0, &id, NULL, 0), -ENOENT);

    // Destroy the listener: accept is EINVAL.
    memset(&id, 0, sizeof id);
    id.idiag_sport = htons(lport);
    id.idiag_src[0] = lo;
    id.idiag_cookie[0] = id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    want("destroy the listener", send_req(nl, SOCK_DESTROY, NLM_F_ACK, AF_INET, IPPROTO_TCP, 0, 0, &id, NULL, 0), 0);
    want("accept after", accept4(lis, NULL, NULL, SOCK_NONBLOCK) < 0 ? -errno : 0, -EINVAL);

    // Destroy the UDP socket by its cookie (src its own end, as QUIC's
    // close does): ECONNABORTED before anything else, then nothing.
    memset(&id, 0, sizeof id);
    id.idiag_sport = htons(uport);
    id.idiag_src[0] = lo;
    id.idiag_cookie[0] = (uint32_t)cookie_of(udp);
    id.idiag_cookie[1] = (uint32_t)(cookie_of(udp) >> 32);
    want("destroy the udp socket", send_req(nl, SOCK_DESTROY, NLM_F_ACK, AF_INET, IPPROTO_UDP, 0, 0, &id, NULL, 0), 0);
    want("udp recv after destroy", recv(udp, b1, sizeof b1, MSG_DONTWAIT) < 0 ? -errno : 0, -ECONNABORTED);
    want("then nothing", recv(udp, b1, sizeof b1, MSG_DONTWAIT) < 0 ? -errno : 0, -EAGAIN);

    // A socket let go is told to the group listening for its kind (UDP over
    // IPv4: group 2), with its cookie.
    int mon = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = 1 << (SKNLGRP_INET_UDP_DESTROY - 1)};
    want("bind to the group", bind(mon, (struct sockaddr *)&sa, sizeof sa), 0);
    int gone = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in g = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    bind(gone, (struct sockaddr *)&g, sizeof g);
    uint64_t gone_cookie = cookie_of(gone);
    close(gone);
    struct pollfd mp = {.fd = mon, .events = POLLIN};
    int heard = 0;
    while (!heard && poll(&mp, 1, 3000) == 1) {
        n = recv(mon, buf, sizeof buf, 0);
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; n > 0 && NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            struct inet_diag_msg *m = NLMSG_DATA(h);
            if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY && msg_cookie(m) == gone_cookie) {
                heard = 1;
                want("its state", m->idiag_state, 7);
                want("its length", h->nlmsg_len, 96);
            }
        }
    }
    want("the socket let go is told", heard, 1);
    close(mon);

    close(srv);
    close(cli);
    close(lis);
    close(udp);
    close(nl);
    if (!failed) printf("sockdiag ok\n");
    return failed;
}
