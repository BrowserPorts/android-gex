// IPv6 sockets on a machine reached by IPv4: what one says of itself,
// IPV6_V6ONLY, binding :: and an address the machine does not have,
// datagrams and a connection between IPv6 and IPv4 sockets over
// IPv4-mapped loopback, and the family rules. Prints an answer a line and
// checks them against Linux 7.0's. (::1 is not asked: here it is IPv4's
// loopback.)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "udp6: 0\n"
    "domain 10 type 2 protocol 17 v6only 0\n"
    "a short address: -22\n"
    "an IPv4 address: -22\n"
    "an address not here: -99\n"
    "bind ::: 0\n"
    "its name: family 10 ::, 28 bytes, a port 1\n"
    "ipv4 to it: 2\n"
    "it got: 2, from family 10 ::ffff:127.0.0.1, 28 bytes\n"
    "back: 2\n"
    "ipv4 got: 2, from family 2 127.0.0.1\n"
    "v6only: 0, now 1\n"
    "v6only on an IPv4 socket: -92\n"
    "tcp6 listening: domain 10, protocol 6\n"
    "ipv4 connect: 0\n"
    "accepted: 1, the peer family 10 ::ffff:127.0.0.1, 28 bytes\n"
    "tcp6 connect to an IPv4 address: -22\n"
;

static char out_buf[4096];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[512];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static int opt(int s, int level, int name) {
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(s, level, name, &v, &l) != 0) return -errno;
    return v;
}

static const char *show(struct sockaddr_in6 *a) {
    static char b[64];
    char t[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &a->sin6_addr, t, sizeof t);
    snprintf(b, sizeof b, "family %d %s", a->sin6_family, t);
    return b;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    SAY("udp6: %d\n", u > 0 ? 0 : -errno);
    SAY("domain %d type %d protocol %d v6only %d\n", opt(u, SOL_SOCKET, SO_DOMAIN), opt(u, SOL_SOCKET, SO_TYPE), opt(u, SOL_SOCKET, SO_PROTOCOL),
        opt(u, IPPROTO_IPV6, IPV6_V6ONLY));
    struct sockaddr_in6 any = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT};
    SAY("a short address: %d\n", bind(u, (struct sockaddr *)&any, 20) == 0 ? 0 : -errno);
    struct sockaddr_in v4 = {.sin_family = AF_INET};
    SAY("an IPv4 address: %d\n", bind(u, (struct sockaddr *)&v4, sizeof v4) == 0 ? 0 : -errno);
    struct sockaddr_in6 far = {.sin6_family = AF_INET6};
    inet_pton(AF_INET6, "2001:db8::1", &far.sin6_addr);
    SAY("an address not here: %d\n", bind(u, (struct sockaddr *)&far, sizeof far) == 0 ? 0 : -errno);
    SAY("bind ::: %d\n", bind(u, (struct sockaddr *)&any, sizeof any) == 0 ? 0 : -errno);
    struct sockaddr_in6 me;
    socklen_t ml = sizeof me;
    getsockname(u, (struct sockaddr *)&me, &ml);
    SAY("its name: %s, %u bytes, a port %d\n", show(&me), ml, me.sin6_port != 0);

    // A datagram from an IPv4 socket, to the IPv6 one, through
    // 127.0.0.1.
    int u4 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = me.sin6_port, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    SAY("ipv4 to it: %zd\n", sendto(u4, "hi", 2, 0, (struct sockaddr *)&to, sizeof to));
    char buf[16];
    struct sockaddr_in6 from;
    socklen_t fl = sizeof from;
    ssize_t n = recvfrom(u, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
    SAY("it got: %zd, from %s, %u bytes\n", n, show(&from), fl);
    // And back, to the mapped address it came from.
    SAY("back: %zd\n", sendto(u, "yo", 2, 0, (struct sockaddr *)&from, fl));
    struct sockaddr_in f4;
    socklen_t f4l = sizeof f4;
    n = recvfrom(u4, buf, sizeof buf, 0, (struct sockaddr *)&f4, &f4l);
    SAY("ipv4 got: %zd, from family %d %s\n", n, f4.sin_family, inet_ntoa(f4.sin_addr));
    close(u4);
    close(u);

    // IPv6 alone: an IPv4-mapped address is no way out.
    int o = socket(AF_INET6, SOCK_DGRAM, 0);
    int one = 1;
    SAY("v6only: %d, now %d\n", setsockopt(o, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == 0 ? 0 : -errno, opt(o, IPPROTO_IPV6, IPV6_V6ONLY));
    close(o);
    int s4 = socket(AF_INET, SOCK_DGRAM, 0);
    SAY("v6only on an IPv4 socket: %d\n", setsockopt(s4, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == 0 ? 0 : -errno);
    close(s4);

    // A connection: an IPv4 client to an IPv6 listener on ::.
    int l = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    bind(l, (struct sockaddr *)&any, sizeof any);
    listen(l, 1);
    struct sockaddr_in6 ln;
    socklen_t lnl = sizeof ln;
    getsockname(l, (struct sockaddr *)&ln, &lnl);
    SAY("tcp6 listening: domain %d, protocol %d\n", opt(l, SOL_SOCKET, SO_DOMAIN), opt(l, SOL_SOCKET, SO_PROTOCOL));
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in cto = {.sin_family = AF_INET, .sin_port = ln.sin6_port, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    SAY("ipv4 connect: %d\n", connect(c, (struct sockaddr *)&cto, sizeof cto) == 0 ? 0 : -errno);
    struct sockaddr_in6 peer;
    socklen_t pl = sizeof peer;
    int a = accept(l, (struct sockaddr *)&peer, &pl);
    SAY("accepted: %d, the peer %s, %u bytes\n", a > 0, show(&peer), pl);
    int t6 = socket(AF_INET6, SOCK_STREAM, 0);
    SAY("tcp6 connect to an IPv4 address: %d\n", connect(t6, (struct sockaddr *)&cto, sizeof cto) == 0 ? 0 : -errno);
    close(t6);
    close(a);
    close(c);
    close(l);

    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("ipv6: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "ipv6 ok\n" : "ipv6 done\n");
    return 0;
}
