// Routes over NETLINK_ROUTE (net/ipv4/fib_*.c, net/ipv6/route.c and
// ip6_fib.c), as Android's netd makes them: in numbered tables, through a
// device of its own (two dummy links made here, one up and one down).
// Added, checked, dumped in each family's order and layout, announced to
// the route groups, deleted by Linux's matching rules (IPv4's scope
// exactly), flushed as netd flushes a table (a dump, each route sent back
// to be deleted), and gone with their device. And the kernel's local
// route for 127.0.0.1. Run as root.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failed;
static int nl;
static unsigned seq;

struct req {
    struct nlmsghdr h;
    union {
        struct rtmsg r;
        struct ifinfomsg i;
    };
    char attrs[512];
};

static void add(struct req *m, int type, const void *data, int len) {
    struct rtattr *a = (struct rtattr *)((char *)m + NLMSG_ALIGN(m->h.nlmsg_len));
    a->rta_type = type;
    a->rta_len = RTA_LENGTH(len);
    if (len) memcpy(RTA_DATA(a), data, len);
    m->h.nlmsg_len = NLMSG_ALIGN(m->h.nlmsg_len) + RTA_ALIGN(a->rta_len);
}

static int ack(struct req *m) {
    if (send(nl, m, m->h.nlmsg_len, 0) < 0) return -1000 - errno;
    char buf[8192];
    for (;;) {
        int n = recv(nl, buf, sizeof buf, 0);
        if (n < 0) return -2000 - errno;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n))
            if (h->nlmsg_seq == m->h.nlmsg_seq && h->nlmsg_type == NLMSG_ERROR) return -((struct nlmsgerr *)NLMSG_DATA(h))->error;
    }
}

static void want(const char *what, int got, int err) {
    if (got != err) {
        printf("routes: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

// A dummy link, up or down; its index.
static int dummy(const char *name, int up) {
    struct req m;
    memset(&m, 0, sizeof m);
    m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    m.h.nlmsg_type = RTM_NEWLINK;
    m.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    m.h.nlmsg_seq = ++seq;
    m.i.ifi_flags = m.i.ifi_change = up ? IFF_UP : 0;
    add(&m, IFLA_IFNAME, name, strlen(name) + 1);
    struct rtattr *li = (struct rtattr *)((char *)&m + NLMSG_ALIGN(m.h.nlmsg_len));
    add(&m, IFLA_LINKINFO, NULL, 0);
    add(&m, IFLA_INFO_KIND, "dummy", 5);
    li->rta_len = (char *)&m + m.h.nlmsg_len - (char *)li;
    if (ack(&m)) return -1;
    return if_nametoindex(name);
}

static int unlink_dev(const char *name) {
    struct req m;
    memset(&m, 0, sizeof m);
    m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    m.h.nlmsg_type = RTM_DELLINK;
    m.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    m.h.nlmsg_seq = ++seq;
    add(&m, IFLA_IFNAME, name, strlen(name) + 1);
    return ack(&m);
}

static int set_up(int index, int up) {
    struct req m;
    memset(&m, 0, sizeof m);
    m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    m.h.nlmsg_type = RTM_NEWLINK;
    m.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    m.h.nlmsg_seq = ++seq;
    m.i.ifi_index = index;
    m.i.ifi_flags = up ? IFF_UP : 0;
    m.i.ifi_change = IFF_UP;
    return ack(&m);
}

// A route request, as netd's modifyIpRoute writes one.
struct route {
    int family, dst_len, type, scope, protocol, tos;
    unsigned table, oif, priority, mtu;
    const char *dst, *gw;
};

static int route(int kind, int flags, struct route *r) {
    struct req m;
    memset(&m, 0, sizeof m);
    m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    m.h.nlmsg_type = kind;
    m.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    m.h.nlmsg_seq = ++seq;
    m.r.rtm_family = r->family;
    m.r.rtm_dst_len = r->dst_len;
    m.r.rtm_tos = r->tos;
    m.r.rtm_protocol = r->protocol ? r->protocol : RTPROT_STATIC;
    m.r.rtm_scope = r->scope;
    m.r.rtm_type = r->type ? r->type : RTN_UNICAST;
    add(&m, RTA_TABLE, &r->table, 4);
    unsigned char a[16];
    int alen = r->family == AF_INET ? 4 : 16;
    if (r->dst && inet_pton(r->family, r->dst, a) == 1) add(&m, RTA_DST, a, alen);
    if (r->oif) add(&m, RTA_OIF, &r->oif, 4);
    if (r->gw && inet_pton(r->family, r->gw, a) == 1) add(&m, RTA_GATEWAY, a, alen);
    if (r->mtu) {
        struct rtattr *mx = (struct rtattr *)((char *)&m + NLMSG_ALIGN(m.h.nlmsg_len));
        add(&m, RTA_METRICS, NULL, 0);
        add(&m, RTAX_MTU, &r->mtu, 4);
        mx->rta_len = (char *)&m + m.h.nlmsg_len - (char *)mx;
    }
    if (r->priority) add(&m, RTA_PRIORITY, &r->priority, 4);
    return ack(&m);
}

// The dumped routes of a family in table `table`, whole messages, in order.
static int dump(int family, unsigned table, unsigned char out[][256], int *lens, int max) {
    struct req m;
    memset(&m, 0, sizeof m);
    m.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    m.h.nlmsg_type = RTM_GETROUTE;
    m.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    m.h.nlmsg_seq = ++seq;
    m.r.rtm_family = family;
    if (send(nl, &m, m.h.nlmsg_len, 0) < 0) return -1;
    int count = 0;
    char buf[8192];
    for (;;) {
        int n = recv(nl, buf, sizeof buf, 0);
        if (n <= 0) return -1;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE) return count;
            if (h->nlmsg_type != RTM_NEWROUTE) continue;
            struct rtmsg *r = NLMSG_DATA(h);
            int len = h->nlmsg_len - NLMSG_LENGTH(sizeof *r);
            unsigned t = r->rtm_table;
            for (struct rtattr *a = RTM_RTA(r); RTA_OK(a, len); a = RTA_NEXT(a, len))
                if (a->rta_type == RTA_TABLE) t = *(unsigned *)RTA_DATA(a);
            if (t == table && count < max) {
                int body = h->nlmsg_len - 16;
                memcpy(out[count], (char *)h + 16, body < 256 ? body : 256);
                lens[count++] = body;
            }
        }
    }
}

static void hexout(const char *what, const unsigned char *b, int n) {
    printf("routes: %s:", what);
    for (int i = 0; i < n; i++) printf(" %02x", b[i]);
    printf("\n");
}

// A message's body as expected, from its bytes.
static void same(const char *what, const unsigned char *got, int glen, const unsigned char *want_b, int wlen) {
    if (glen != wlen || memcmp(got, want_b, wlen)) {
        printf("routes: %s differs (length %d, want %d)\n", what, glen, wlen);
        hexout("got ", got, glen);
        hexout("want", want_b, wlen);
        failed = 1;
    }
}

int main(void) {
    nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    int mon = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE};
    if (nl < 0 || mon < 0 || bind(mon, (struct sockaddr *)&sa, sizeof sa)) {
        printf("routes: sockets (errno %d)\n", errno);
        return 1;
    }
    int up = dummy("gexrt0", 1), down = dummy("gexrt1", 0);
    if (up <= 0 || down <= 0) {
        printf("routes: dummy links (%d, %d)\n", up, down);
        return 1;
    }

    // IPv4: a connected route, netd's shape.
    char buf[8192];
    while (recv(mon, buf, sizeof buf, 0) > 0) {
    }
    struct route c = {AF_INET, 16, 0, RT_SCOPE_LINK, 0, 0, 1003, up, 0, 0, "10.99.0.0", NULL};
    want("a connected route", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &c), 0);
    want("again, exclusive", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &c), EEXIST);
    // The IPv4 group heard it: a new key, 0x600. (A dummy link brought
    // up may have the IPv6 group hear of its own routes as well.)
    int heard = 0;
    for (int n; (n = recv(mon, buf, sizeof buf, 0)) > 0;) {
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n)) {
            struct rtmsg *r = NLMSG_DATA(h);
            if (h->nlmsg_type != RTM_NEWROUTE || r->rtm_family != AF_INET) continue;
            heard++;
            if (h->nlmsg_flags != (NLM_F_CREATE | NLM_F_EXCL) || r->rtm_dst_len != 16) {
                printf("routes: the notice of a new route (flags %#x, length %d)\n", h->nlmsg_flags, r->rtm_dst_len);
                failed = 1;
            }
        }
    }
    if (heard != 1) {
        printf("routes: %d IPv4 notices of the new route\n", heard);
        failed = 1;
    }
    // Through a gateway it reaches, with an MTU and a priority.
    struct route g = {AF_INET, 0, 0, RT_SCOPE_UNIVERSE, 0, 0, 1003, up, 5, 1400, NULL, "10.99.0.1"};
    want("a default route by a gateway", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &g), 0);
    struct route g2 = {AF_INET, 0, 0, RT_SCOPE_UNIVERSE, 0, 0, 1004, up, 0, 0, NULL, "10.98.0.1"};
    want("a gateway nothing reaches", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &g2), ENETUNREACH);
    struct route d = {AF_INET, 16, 0, RT_SCOPE_LINK, 0, 0, 1003, down, 0, 0, "10.97.0.0", NULL};
    want("through a device that is down", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &d), ENETDOWN);
    struct route u = {AF_INET, 0, RTN_UNREACHABLE, RT_SCOPE_UNIVERSE, 0, 0, 1003, 0, 99, 0, NULL, NULL};
    want("unreachable", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &u), 0);
    struct route u5 = u;
    u5.priority = 5;
    want("unreachable at the gateway route's priority", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &u5), EEXIST);
    struct route ub = u;
    ub.oif = up;
    ub.priority = 98;
    want("unreachable with a device", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &ub), EINVAL);
    struct route hb = {AF_INET, 8, 0, RT_SCOPE_LINK, 0, 0, 1003, up, 0, 0, "10.99.0.0", NULL};
    want("host bits", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &hb), EINVAL);
    hb.dst_len = 33;
    want("a prefix past 32", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &hb), EINVAL);
    struct route ecn = c;
    ecn.tos = 1;
    want("ECN bits", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &ecn), EINVAL);
    struct route nc = c;
    nc.dst = "10.96.0.0";
    want("not there, no CREATE", route(RTM_NEWROUTE, 0, &nc), ENOENT);
    struct route noif = c;
    noif.oif = 0;
    noif.dst = "10.95.0.0";
    want("no device", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &noif), ENODEV);

    // The table's routes as a dump gives them, in order.
    unsigned char got[8][256];
    int lens[8];
    int count = dump(AF_INET, 1003, got, lens, 8);
    if (count != 3) {
        printf("routes: IPv4 table 1003 has %d routes, want 3\n", count);
        failed = 1;
    } else {
        // 0.0.0.0/0 unreachable at 99, 0.0.0.0/0 by the gateway at 5?
        // Same address: longer prefix first, then priority ascending.
        unsigned char gw[] = {2, 0, 0, 0, 0xfc, 4, 0, 1, 0, 0, 0, 0, 8, 0, 15, 0, 0xeb, 3, 0, 0, 8, 0, 6, 0, 5, 0, 0, 0, 12, 0, 8, 0, 8, 0, 2, 0, 0x78, 5, 0, 0, 8, 0, 5, 0, 10, 99, 0, 1, 8, 0, 4, 0, (unsigned char)up, 0, 0, 0};
        unsigned char un[] = {2, 0, 0, 0, 0xfc, 4, 0, 7, 0, 0, 0, 0, 8, 0, 15, 0, 0xeb, 3, 0, 0, 8, 0, 6, 0, 99, 0, 0, 0};
        unsigned char cn[] = {2, 16, 0, 0, 0xfc, 4, 0xfd, 1, 0, 0, 0, 0, 8, 0, 15, 0, 0xeb, 3, 0, 0, 8, 0, 1, 0, 10, 99, 0, 0, 8, 0, 4, 0, (unsigned char)up, 0, 0, 0};
        same("the gateway route", got[0], lens[0], gw, sizeof gw);
        same("the unreachable route", got[1], lens[1], un, sizeof un);
        same("the connected route", got[2], lens[2], cn, sizeof cn);
    }

    // Deleted as Linux matches: IPv4's scope exactly (255 any).
    struct route wrongscope = c;
    wrongscope.scope = RT_SCOPE_UNIVERSE;
    want("delete, another scope", route(RTM_DELROUTE, 0, &wrongscope), ESRCH);
    struct route anyscope = c;
    anyscope.scope = RT_SCOPE_NOWHERE;
    anyscope.oif = 0;
    want("delete, any scope", route(RTM_DELROUTE, 0, &anyscope), 0);
    want("delete again", route(RTM_DELROUTE, 0, &anyscope), ESRCH);
    struct route missing = c;
    missing.table = 4321;
    want("delete in a table not there", route(RTM_DELROUTE, 0, &missing), ESRCH);

    // IPv6.
    struct route s6 = {AF_INET6, 64, 0, 0, 0, 0, 1003, up, 0, 0, "2001:db8::", NULL};
    want("an IPv6 route", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &s6), 0);
    want("again, exclusive", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &s6), EEXIST);
    want("again, the same nexthop", route(RTM_NEWROUTE, NLM_F_CREATE, &s6), EEXIST);
    struct route r6 = {AF_INET6, 0, RTN_UNREACHABLE, 0, 0, 0, 1003, 0, 0, 0, NULL, NULL};
    want("IPv6 unreachable", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &r6), 0);
    struct route d6 = s6;
    d6.oif = down;
    d6.dst = "2001:db8:1::";
    want("IPv6 through a device that is down", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &d6), ENETDOWN);
    struct route t6 = s6;
    t6.tos = 4;
    want("IPv6 with a tos", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &t6), EINVAL);
    struct route gw6 = {AF_INET6, 48, 0, 0, 0, 0, 1003, up, 0, 0, "2001:db8:2::", "fe80::1"};
    want("IPv6 by a link-local gateway", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &gw6), 0);
    struct route gwn = {AF_INET6, 48, 0, 0, 0, 0, 1004, 0, 0, 0, "2001:db8:3::", "2001:db8:9::1"};
    want("IPv6 by a gateway nothing reaches", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &gwn), EHOSTUNREACH);
    count = dump(AF_INET6, 1003, got, lens, 8);
    if (count != 3) {
        printf("routes: IPv6 table 1003 has %d routes, want 3\n", count);
        failed = 1;
    } else {
        // 2001:db8::/64 before 2001:db8:2::/48 (bit 46) before ::/0.
        unsigned char a[] = {10, 64, 0, 0, 0xfc, 4, 0, 1, 0, 0, 0, 0, 8, 0, 15, 0, 0xeb, 3, 0, 0, 20, 0, 1, 0, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 4, 0, 0, 8, 0, 4, 0, (unsigned char)up, 0, 0, 0, 36, 0, 12, 0};
        unsigned char tail[40] = {0};
        tail[32] = 5;
        tail[34] = 20;
        unsigned char full[sizeof a + 40];
        memcpy(full, a, sizeof a);
        memcpy(full + sizeof a, tail, 40);
        same("the IPv6 route", got[0], lens[0], full, sizeof full);
        if (got[1][1] != 48 || got[2][1] != 0 || got[2][7] != RTN_UNREACHABLE) {
            printf("routes: IPv6 order (%d, %d, type %d)\n", got[1][1], got[2][1], got[2][7]);
            failed = 1;
        }
    }

    // A table flushed as netd flushes it: each dumped route sent back.
    count = dump(AF_INET6, 1003, got, lens, 8);
    for (int i = 0; i < count; i++) {
        struct req m;
        memset(&m, 0, sizeof m);
        m.h.nlmsg_len = 16 + lens[i];
        m.h.nlmsg_type = RTM_DELROUTE;
        m.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        m.h.nlmsg_seq = ++seq;
        memcpy(&m.r, got[i], lens[i]);
        want("a flushed route", ack(&m), 0);
    }
    if (dump(AF_INET6, 1003, got, lens, 8) != 0) {
        printf("routes: IPv6 table 1003 not empty after the flush\n");
        failed = 1;
    }

    // The kernel's local route for 127.0.0.1.
    count = dump(AF_INET, 255, got, lens, 8);
    int found = 0;
    unsigned char lo[] = {2, 32, 0, 0, 255, 2, 254, 2, 0, 0, 0, 0, 8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 127, 0, 0, 1, 8, 0, 7, 0, 127, 0, 0, 1, 8, 0, 4, 0, 1, 0, 0, 0};
    for (int i = 0; i < count; i++)
        if (lens[i] == (int)sizeof lo && !memcmp(got[i], lo, sizeof lo)) found = 1;
    if (!found) {
        printf("routes: no local route for 127.0.0.1 among %d\n", count);
        failed = 1;
    }

    // A device going down takes its routes (IPv4 and IPv6).
    want("IPv6 again", route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &s6), 0);
    want("down", set_up(up, 0), 0);
    // IPv4 keeps its unreachable route; IPv6's was flushed above.
    if (dump(AF_INET, 1003, got, lens, 8) != 1 || dump(AF_INET6, 1003, got, lens, 8) != 0) {
        printf("routes: after the device went down, IPv4 %d (want 1), IPv6 %d (want 0)\n", dump(AF_INET, 1003, got, lens, 8), dump(AF_INET6, 1003, got, lens, 8));
        failed = 1;
    }

    unlink_dev("gexrt0");
    unlink_dev("gexrt1");
    // What is left of the test's in the tables: the reject routes.
    route(RTM_DELROUTE, 0, &u);
    route(RTM_DELROUTE, 0, &r6);
    route(RTM_DELROUTE, 0, &gwn);
    if (failed) return 1;
    printf("routes ok\n");
    return 0;
}
