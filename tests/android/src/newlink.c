// Links made and deleted over NETLINK_ROUTE (net/core/rtnetlink.c's
// rtnl_newlink and rtnl_dellink), of two kinds GKI builds in: dummy
// (drivers/net/dummy.c), whose dummy0 a GKI kernel has from boot, and
// xfrm (net/xfrm/xfrm_interface_core.c), which Android's netd makes at
// start to learn whether the kernel has it. The checks in Linux's order:
// the kind's own, then the device named (EXCL, REPLACE, CREATE), then
// making it; what a dump says of each; the notice to the link group; and
// CAP_NET_ADMIN. Run as root.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef IFLA_XFRM_LINK
#define IFLA_XFRM_LINK 1
#define IFLA_XFRM_IF_ID 2
#endif

static int failed;
static int nl;
static unsigned seq;

struct msg {
    struct nlmsghdr h;
    struct ifinfomsg i;
    char attrs[512];
};

static void add(struct msg *m, int type, const void *data, int len) {
    struct rtattr *a = (struct rtattr *)((char *)m + NLMSG_ALIGN(m->h.nlmsg_len));
    a->rta_type = type;
    a->rta_len = RTA_LENGTH(len);
    if (len) memcpy(RTA_DATA(a), data, len);
    m->h.nlmsg_len = NLMSG_ALIGN(m->h.nlmsg_len) + RTA_ALIGN(a->rta_len);
}

static struct rtattr *begin(struct msg *m, int type) {
    struct rtattr *a = (struct rtattr *)((char *)m + NLMSG_ALIGN(m->h.nlmsg_len));
    add(m, type, NULL, 0);
    return a;
}

static void end(struct msg *m, struct rtattr *a) {
    a->rta_len = (char *)m + m->h.nlmsg_len - (char *)a;
}

static void start(struct msg *m, int type, int flags, int index, unsigned ifflags, unsigned change) {
    memset(m, 0, sizeof *m);
    m->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    m->h.nlmsg_type = type;
    m->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    m->h.nlmsg_seq = ++seq;
    m->i.ifi_family = AF_UNSPEC;
    m->i.ifi_index = index;
    m->i.ifi_flags = ifflags;
    m->i.ifi_change = change;
}

static void name(struct msg *m, const char *n) {
    add(m, IFLA_IFNAME, n, strlen(n) + 1);
}

static void kind(struct msg *m, const char *k, int link, int if_id) {
    struct rtattr *li = begin(m, IFLA_LINKINFO);
    add(m, IFLA_INFO_KIND, k, strlen(k));
    if (link >= 0 || if_id >= 0) {
        struct rtattr *d = begin(m, IFLA_INFO_DATA);
        if (link >= 0) add(m, IFLA_XFRM_LINK, &link, 4);
        if (if_id >= 0) add(m, IFLA_XFRM_IF_ID, &if_id, 4);
        end(m, d);
    }
    end(m, li);
}

// The request's answer: its error (0 for an ack).
static int send_req(struct msg *m) {
    if (send(nl, m, m->h.nlmsg_len, 0) < 0) return errno;
    char buf[8192];
    for (;;) {
        int n = recv(nl, buf, sizeof buf, 0);
        if (n < 0) return -1000 - errno;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq == m->h.nlmsg_seq && h->nlmsg_type == NLMSG_ERROR) return -((struct nlmsgerr *)NLMSG_DATA(h))->error;
        }
    }
}

static void want(const char *what, int got, int err) {
    if (got != err) {
        printf("newlink: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

static int make(const char *n, const char *k, int link, int if_id, int flags, unsigned up) {
    struct msg m;
    start(&m, RTM_NEWLINK, flags, 0, up, up);
    if (n) name(&m, n);
    if (k) kind(&m, k, link, if_id);
    return send_req(&m);
}

static int del(const char *n) {
    struct msg m;
    start(&m, RTM_DELLINK, 0, 0, 0, 0);
    name(&m, n);
    return send_req(&m);
}

// A link as RTM_GETLINK says it.
struct link {
    int found, index, type;
    unsigned flags, mtu, min_mtu, max_mtu, txqlen, link, has_link, xlink, xid;
    int addr_len;
    unsigned char addr[8];
    char kind[16], qdisc[16];
    int operstate;
};

static void parse(struct ifinfomsg *i, int len, struct link *l) {
    memset(l, 0, sizeof *l);
    l->found = 1;
    l->index = i->ifi_index;
    l->type = i->ifi_type;
    l->flags = i->ifi_flags;
    l->operstate = -1;
    for (struct rtattr *a = IFLA_RTA(i); RTA_OK(a, len); a = RTA_NEXT(a, len)) {
        void *d = RTA_DATA(a);
        switch (a->rta_type) {
        case IFLA_MTU: l->mtu = *(unsigned *)d; break;
        case IFLA_MIN_MTU: l->min_mtu = *(unsigned *)d; break;
        case IFLA_MAX_MTU: l->max_mtu = *(unsigned *)d; break;
        case IFLA_TXQLEN: l->txqlen = *(unsigned *)d; break;
        case IFLA_LINK: l->link = *(unsigned *)d; l->has_link = 1; break;
        case IFLA_OPERSTATE: l->operstate = *(unsigned char *)d; break;
        case IFLA_QDISC: snprintf(l->qdisc, sizeof l->qdisc, "%s", (char *)d); break;
        case IFLA_ADDRESS:
            l->addr_len = RTA_PAYLOAD(a);
            memcpy(l->addr, d, l->addr_len < 8 ? l->addr_len : 8);
            break;
        case IFLA_LINKINFO: {
            int ilen = RTA_PAYLOAD(a);
            for (struct rtattr *b = RTA_DATA(a); RTA_OK(b, ilen); b = RTA_NEXT(b, ilen)) {
                if (b->rta_type == IFLA_INFO_KIND) snprintf(l->kind, sizeof l->kind, "%.*s", (int)RTA_PAYLOAD(b), (char *)RTA_DATA(b));
                if (b->rta_type == IFLA_INFO_DATA) {
                    int dlen = RTA_PAYLOAD(b);
                    for (struct rtattr *c = RTA_DATA(b); RTA_OK(c, dlen); c = RTA_NEXT(c, dlen)) {
                        if (c->rta_type == IFLA_XFRM_LINK) l->xlink = *(unsigned *)RTA_DATA(c);
                        if (c->rta_type == IFLA_XFRM_IF_ID) l->xid = *(unsigned *)RTA_DATA(c);
                    }
                }
            }
            break;
        }
        }
    }
}

static struct link get(const char *n) {
    struct msg m;
    struct link l = {0};
    start(&m, RTM_GETLINK, 0, 0, 0, 0);
    m.h.nlmsg_flags = NLM_F_REQUEST;
    name(&m, n);
    if (send(nl, &m, m.h.nlmsg_len, 0) < 0) return l;
    char buf[8192];
    int len = recv(nl, buf, sizeof buf, 0);
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    if (len > 0 && NLMSG_OK(h, (unsigned)len) && h->nlmsg_type == RTM_NEWLINK)
        parse(NLMSG_DATA(h), h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)), &l);
    return l;
}

static void is(const char *what, long got, long expect) {
    if (got != expect) {
        printf("newlink: %s: want %#lx, got %#lx\n", what, expect, got);
        failed = 1;
    }
}

static void is_s(const char *what, const char *got, const char *expect) {
    if (strcmp(got, expect)) {
        printf("newlink: %s: want \"%s\", got \"%s\"\n", what, expect, got);
        failed = 1;
    }
}

int main(void) {
    nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    int mon = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK};
    if (nl < 0 || mon < 0 || bind(mon, (struct sockaddr *)&sa, sizeof sa)) {
        printf("newlink: sockets (errno %d)\n", errno);
        return 1;
    }

    // A dummy link, up.
    want("a dummy", make("gexdm0", "dummy", -1, -1, NLM_F_CREATE | NLM_F_EXCL, IFF_UP), 0);
    // The link group heard it once, with every flag changed.
    char buf[8192];
    int notes = 0;
    unsigned change = 0;
    for (;;) {
        int n = recv(mon, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)n); h = NLMSG_NEXT(h, n)) {
            struct ifinfomsg *i = NLMSG_DATA(h);
            struct link l;
            parse(i, h->nlmsg_len - NLMSG_LENGTH(sizeof *i), &l);
            if (h->nlmsg_type == RTM_NEWLINK && l.index == get("gexdm0").index) {
                if (!notes) change = i->ifi_change;
                notes++;
            }
        }
    }
    is("notices of a new link", notes, 1);
    is("the notice's change", change, 0xffffffff);
    struct link d = get("gexdm0");
    is("dummy: found", d.found, 1);
    is("dummy: type", d.type, 1);
    is("dummy: flags", d.flags, IFF_UP | IFF_BROADCAST | IFF_NOARP | IFF_RUNNING | IFF_LOWER_UP);
    is("dummy: mtu", d.mtu, 1500);
    is("dummy: min mtu", d.min_mtu, 0);
    is("dummy: max mtu", d.max_mtu, 0);
    is("dummy: txqlen", d.txqlen, 1000);
    is("dummy: operstate", d.operstate, 0);
    is("dummy: link", d.has_link, 0);
    is("dummy: address length", d.addr_len, 6);
    is("dummy: address unicast and local", d.addr[0] & 3, 2);
    is_s("dummy: kind", d.kind, "dummy");
    is_s("dummy: qdisc", d.qdisc, "noqueue");
    // The kernel's own, from boot where the driver is built in (GKI's
    // numdummies is 1; a distribution's module may be loaded with 0).
    struct link d0 = get("dummy0");
    if (d0.found) is_s("dummy0: kind", d0.kind, "dummy");

    want("again, exclusive", make("gexdm0", "dummy", -1, -1, NLM_F_CREATE | NLM_F_EXCL, 0), EEXIST);
    want("again, replacing", make("gexdm0", "dummy", -1, -1, NLM_F_CREATE | NLM_F_REPLACE, 0), EOPNOTSUPP);
    want("again, a change", make("gexdm0", "dummy", -1, -1, NLM_F_CREATE, 0), 0);
    want("a dummy's data", make("gexdm0", "dummy", 1, 1, 0, 0), EOPNOTSUPP);
    want("one not there, not made", make("gexdm9", "dummy", -1, -1, 0, 0), ENODEV);
    want("a kind not there", make("gexdm9", "nosuchkind", -1, -1, NLM_F_CREATE, 0), EOPNOTSUPP);
    want("no kind", make("gexdm9", NULL, -1, -1, NLM_F_CREATE, 0), EOPNOTSUPP);
    want("tun", make("gexdm9", "tun", -1, -1, NLM_F_CREATE, 0), EOPNOTSUPP);
    want("lo, exclusive", make("lo", NULL, -1, -1, NLM_F_CREATE | NLM_F_EXCL, 0), EEXIST);

    // A dummy's address: six bytes, not multicast, not zero.
    struct msg m;
    static const unsigned char good[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, multi[6] = {0x01, 0, 0, 0, 0, 1}, zero[6];
    start(&m, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0, 0, 0);
    name(&m, "gexdm1");
    add(&m, IFLA_ADDRESS, good, 5);
    kind(&m, "dummy", -1, -1);
    want("a short address", send_req(&m), EINVAL);
    start(&m, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0, 0, 0);
    name(&m, "gexdm1");
    add(&m, IFLA_ADDRESS, multi, 6);
    kind(&m, "dummy", -1, -1);
    want("a multicast address", send_req(&m), EADDRNOTAVAIL);
    start(&m, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0, 0, 0);
    name(&m, "gexdm1");
    add(&m, IFLA_ADDRESS, zero, 6);
    kind(&m, "dummy", -1, -1);
    want("a zero address", send_req(&m), EADDRNOTAVAIL);
    unsigned mtu = 9000;
    start(&m, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0, 0, 0);
    name(&m, "gexdm1");
    add(&m, IFLA_ADDRESS, good, 6);
    add(&m, IFLA_MTU, &mtu, 4);
    kind(&m, "dummy", -1, -1);
    want("an address and an MTU", send_req(&m), 0);
    struct link d1 = get("gexdm1");
    is("its address", d1.addr_len == 6 && !memcmp(d1.addr, good, 6), 1);
    is("its MTU", d1.mtu, 9000);
    is("down", d1.flags, IFF_BROADCAST | IFF_NOARP);
    is_s("down: qdisc", d1.qdisc, "noop");

    // An xfrm link: an interface id, unique; the link it says.
    want("xfrm without an id", make("gexxf0", "xfrm", 1, 0, NLM_F_CREATE | NLM_F_EXCL, 0), EINVAL);
    want("xfrm", make("gexxf0", "xfrm", 1, 0xffff, NLM_F_CREATE | NLM_F_EXCL, 0), 0);
    want("xfrm, the id taken", make("gexxf1", "xfrm", 1, 0xffff, NLM_F_CREATE | NLM_F_EXCL, 0), EEXIST);
    struct link x = get("gexxf0");
    is("xfrm: type", x.type, 0xfffe);
    is("xfrm: flags", x.flags, IFF_NOARP);
    is("xfrm: mtu", x.mtu, 1500);
    is("xfrm: min mtu", x.min_mtu, 68);
    is("xfrm: max mtu", x.max_mtu, 65535);
    is("xfrm: txqlen", x.txqlen, 1000);
    is("xfrm: address length", x.addr_len, 0);
    is("xfrm: link", x.has_link && x.link == 1, 1);
    is_s("xfrm: kind", x.kind, "xfrm");
    is("xfrm: data link", x.xlink, 1);
    is("xfrm: data id", x.xid, 0xffff);
    want("xfrm: a new id", make("gexxf0", "xfrm", 1, 7, 0, 0), 0);
    is("xfrm: the new id", get("gexxf0").xid, 7);
    want("xfrm: a new link", make("gexxf0", "xfrm", 2, 7, 0, 0), EINVAL);
    want("xfrm: no id", make("gexxf0", "xfrm", 1, 0, 0, 0), EINVAL);
    want("xfrm: up", make("gexxf0", NULL, -1, -1, 0, IFF_UP), 0);
    struct link xu = get("gexxf0");
    is("xfrm up: flags", xu.flags, IFF_UP | IFF_NOARP | IFF_RUNNING | IFF_LOWER_UP);
    is("xfrm up: operstate", xu.operstate, 0);
    is_s("xfrm up: qdisc", xu.qdisc, "noqueue");

    // Without CAP_NET_ADMIN.
    pid_t child = fork();
    if (child == 0) {
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) _exit(2);
        failed = 0;
        want("unprivileged", make("gexdm2", "dummy", -1, -1, NLM_F_CREATE | NLM_F_EXCL, 0), EPERM);
        want("unprivileged delete", del("gexdm0"), EPERM);
        _exit(failed);
    }
    int st;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st)) failed = 1;

    // Gone; lo has no link operations.
    want("delete lo", del("lo"), EOPNOTSUPP);
    want("delete gexdm0", del("gexdm0"), 0);
    want("delete gexdm1", del("gexdm1"), 0);
    want("delete gexxf0", del("gexxf0"), 0);
    want("delete one not there", del("gexdm0"), ENODEV);
    is("gexdm0 gone", get("gexdm0").found, 0);
    if (failed) return 1;
    printf("newlink ok\n");
    return 0;
}
