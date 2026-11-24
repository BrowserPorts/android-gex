// Traffic control over NETLINK_ROUTE as Android's libtcutils uses it, on a
// TUN device of the test's own: clsact added (a notification with
// NLM_F_REPLACE), added again (EEXIST), replaced (a change), dumped (152
// bytes, handle ffff:, parent ffff:fff1), deleted and deleted again
// (EINVAL once the ingress queue exists; ENOENT before), the refusals of a
// bad device, kind (ENOENT into the empty slot, EINVAL over a clsact),
// parent or missing NLM_F_CREATE; then BPF classifiers
// on its ingress block: a SCHED_CLS program by descriptor, direct action,
// named (handle 1, its id and FLAGS_GEN 8 in the dump after a header
// message, the request's flags in the notification), the same again
// (handle 2), asked for (handle 1 found, 0 not), the refusals (no
// clsact, wrong program type, bad descriptor, bad flags, no protocol, a
// protocol mismatch, an unknown kind, clsact's other minor, an empty
// chain), and deleted by priority. As root.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int failed;
static int nl, listener;
static unsigned char rbuf[65536];
static long rlen;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("tc: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static int put_attr(unsigned char *p, int at, int type, const void *data, int len) {
    struct nlattr *a = (struct nlattr *)(p + at);
    a->nla_len = NLA_HDRLEN + len;
    a->nla_type = type;
    memcpy(a + 1, data, len);
    return at + NLA_ALIGN(a->nla_len);
}

// One request with an acknowledgement; its error, and what came before
// the acknowledgement in rbuf/rlen.
static long ask(int type, int flags, int ifindex, uint32_t handle, uint32_t parent, uint32_t info, const unsigned char *attrs, int alen) {
    unsigned char req[1024];
    memset(req, 0, sizeof req);
    struct nlmsghdr *h = (struct nlmsghdr *)req;
    struct tcmsg *t = NLMSG_DATA(h);
    t->tcm_ifindex = ifindex;
    t->tcm_handle = handle;
    t->tcm_parent = parent;
    t->tcm_info = info;
    int len = NLMSG_LENGTH(sizeof *t);
    memcpy(req + NLMSG_ALIGN(len), attrs, alen);
    len = NLMSG_ALIGN(len) + alen;
    h->nlmsg_len = len;
    h->nlmsg_type = type;
    h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    h->nlmsg_seq = 77;
    if (send(nl, req, len, 0) != len) return -errno;
    rlen = 0;
    for (;;) {
        unsigned char b[16384];
        long n = recv(nl, b, sizeof b, 0);
        if (n < 0) return -errno;
        for (struct nlmsghdr *m = (struct nlmsghdr *)b; NLMSG_OK(m, n); m = NLMSG_NEXT(m, n)) {
            if (m->nlmsg_type == NLMSG_ERROR) return ((struct nlmsgerr *)NLMSG_DATA(m))->error;
            memcpy(rbuf + rlen, m, m->nlmsg_len);
            rlen += NLMSG_ALIGN(m->nlmsg_len);
        }
    }
}

// A dump's messages into rbuf/rlen; how many.
static int dump(int type, int ifindex, uint32_t parent) {
    unsigned char req[64];
    memset(req, 0, sizeof req);
    struct nlmsghdr *h = (struct nlmsghdr *)req;
    struct tcmsg *t = NLMSG_DATA(h);
    t->tcm_ifindex = ifindex;
    t->tcm_parent = parent;
    h->nlmsg_len = NLMSG_LENGTH(sizeof *t);
    h->nlmsg_type = type;
    h->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    h->nlmsg_seq = 78;
    send(nl, req, h->nlmsg_len, 0);
    rlen = 0;
    int count = 0;
    for (;;) {
        unsigned char b[32768];
        long n = recv(nl, b, sizeof b, 0);
        if (n <= 0) return count;
        for (struct nlmsghdr *m = (struct nlmsghdr *)b; NLMSG_OK(m, n); m = NLMSG_NEXT(m, n)) {
            if (m->nlmsg_type == NLMSG_DONE || m->nlmsg_type == NLMSG_ERROR) return count;
            memcpy(rbuf + rlen, m, m->nlmsg_len);
            rlen += NLMSG_ALIGN(m->nlmsg_len);
            count++;
        }
    }
}

// The next notification on the listener for this device: its type and flags.
static int notified(int ifindex, int *flags) {
    unsigned char b[16384];
    for (int tries = 0; tries < 50; tries++) {
        long n = recv(listener, b, sizeof b, MSG_DONTWAIT);
        if (n < 0) {
            usleep(20000);
            continue;
        }
        for (struct nlmsghdr *m = (struct nlmsghdr *)b; NLMSG_OK(m, n); m = NLMSG_NEXT(m, n)) {
            struct tcmsg *t = NLMSG_DATA(m);
            if (t->tcm_ifindex == ifindex) {
                *flags = m->nlmsg_flags;
                return m->nlmsg_type;
            }
        }
    }
    return -1;
}

static void drain(void) {
    unsigned char b[16384];
    while (recv(listener, b, sizeof b, MSG_DONTWAIT) > 0) {
    }
}

static struct nlattr *find(struct nlmsghdr *m, int type, int nested_in) {
    unsigned char *p = (unsigned char *)NLMSG_DATA(m) + NLMSG_ALIGN(sizeof(struct tcmsg)), *end = (unsigned char *)m + m->nlmsg_len;
    while (p + NLA_HDRLEN <= end) {
        struct nlattr *a = (struct nlattr *)p;
        if (a->nla_len < NLA_HDRLEN) break;
        if (nested_in && (a->nla_type & NLA_TYPE_MASK) == nested_in) {
            unsigned char *q = (unsigned char *)(a + 1), *qe = p + a->nla_len;
            while (q + NLA_HDRLEN <= qe) {
                struct nlattr *b = (struct nlattr *)q;
                if (b->nla_len < NLA_HDRLEN) break;
                if ((b->nla_type & NLA_TYPE_MASK) == type) return b;
                q += NLA_ALIGN(b->nla_len);
            }
            return NULL;
        }
        if (!nested_in && (a->nla_type & NLA_TYPE_MASK) == type) return a;
        p += NLA_ALIGN(a->nla_len);
    }
    return NULL;
}

static int load(int type) {
    struct bpf_insn insns[2] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = type;
    a.insns = (uintptr_t)insns;
    a.insn_cnt = 2;
    a.license = (uintptr_t)"GPL";
    return syscall(__NR_bpf, BPF_PROG_LOAD, &a, sizeof a);
}

static uint32_t prog_id(int fd) {
    struct bpf_prog_info info;
    memset(&info, 0, sizeof info);
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.info.bpf_fd = fd;
    a.info.info_len = sizeof info;
    a.info.info = (uintptr_t)&info;
    if (syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &a, sizeof a)) return 0;
    return info.id;
}

int main(void) {
    nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    int one = 1;
    want("NETLINK_CAP_ACK", setsockopt(nl, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof one), 0);
    listener = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_TC};
    want("bind a listener", bind(listener, (struct sockaddr *)&sa, sizeof sa), 0);

    // A node of the TUN device (misc 10:200) of the test's own, in a tmpfs.
    char dir[] = "/tmp/tc-test-XXXXXX", node[64];
    if (!mkdtemp(dir) || mount("tmpfs", dir, "tmpfs", 0, NULL)) {
        printf("tc: a tmpfs: %d\n", errno);
        return 1;
    }
    snprintf(node, sizeof node, "%s/tun", dir);
    int tun = mknod(node, S_IFCHR | 0600, makedev(10, 200)) ? -1 : open(node, O_RDWR | O_CLOEXEC);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, "gextc%d");
    if (tun < 0 || ioctl(tun, TUNSETIFF, &ifr)) {
        printf("tc: a TUN device: %d\n", errno);
        return 1;
    }
    int ifindex = if_nametoindex(ifr.ifr_name);

    unsigned char kind[16];
    int klen = put_attr(kind, 0, TCA_KIND, "clsact", 7);
    const uint32_t H = TC_H_MAKE(TC_H_CLSACT, 0);
    want("no such device", ask(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, 99999, H, TC_H_CLSACT, 0, kind, klen), -ENODEV);
    want("delete before any", ask(RTM_DELQDISC, 0, ifindex, H, TC_H_CLSACT, 0, kind, klen), -ENOENT);
    unsigned char ns[16];
    int nslen = put_attr(ns, 0, TCA_KIND, "nosuch", 7);
    want("an unknown kind into the empty slot", ask(RTM_NEWQDISC, NLM_F_CREATE, ifindex, 0, TC_H_CLSACT, 0, ns, nslen), -ENOENT);
    drain();
    want("add clsact", ask(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, ifindex, H, TC_H_CLSACT, 0, kind, klen), 0);
    int fl = 0;
    want("its notification", notified(ifindex, &fl), RTM_NEWQDISC);
    want("its flags", fl, NLM_F_REPLACE);
    want("add again", ask(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, ifindex, H, TC_H_CLSACT, 0, kind, klen), -EEXIST);
    want("replace", ask(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, ifindex, H, TC_H_CLSACT, 0, kind, klen), 0);
    want("its notification", notified(ifindex, &fl), RTM_NEWQDISC);
    want("its flags", fl, 0);
    // The dump: this device's clsact as Linux words it.
    dump(RTM_GETQDISC, 0, 0);
    int seen = 0;
    long n = rlen;
    for (struct nlmsghdr *m = (struct nlmsghdr *)rbuf; NLMSG_OK(m, n); m = NLMSG_NEXT(m, n)) {
        struct tcmsg *t = NLMSG_DATA(m);
        struct nlattr *k = find(m, TCA_KIND, 0);
        if (t->tcm_ifindex == ifindex && k && !strcmp((char *)(k + 1), "clsact")) {
            seen = 1;
            want("clsact's size", m->nlmsg_len, 152);
            want("its handle", t->tcm_handle, H);
            want("its parent", t->tcm_parent, TC_H_CLSACT);
            want("its refcount", t->tcm_info, 1);
        }
    }
    want("the dump has the clsact", seen, 1);
    unsigned char pf[16];
    int pflen = put_attr(pf, 0, TCA_KIND, "pfifo", 6);
    want("clsact at the root", ask(RTM_NEWQDISC, NLM_F_CREATE, ifindex, 0, TC_H_ROOT, 0, kind, klen), -EOPNOTSUPP);
    want("pfifo at the ingress parent", ask(RTM_NEWQDISC, NLM_F_CREATE, ifindex, 0, TC_H_CLSACT, 0, pf, pflen), -EINVAL);
    // With a clsact there, another kind without REPLACE or EXCL is a
    // change of it, and the kind must match.
    want("an unknown kind over the clsact", ask(RTM_NEWQDISC, NLM_F_CREATE, ifindex, 0, TC_H_CLSACT, 0, ns, nslen), -EINVAL);

    // Classifiers on its ingress block.
    int prog = load(BPF_PROG_TYPE_SCHED_CLS), sock_prog = load(BPF_PROG_TYPE_SOCKET_FILTER);
    want("a classifier program", prog >= 0, 1);
    const uint32_t IN = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    const uint32_t info = (17 << 16) | htons(ETH_P_ALL);
    unsigned char bpf[512];
    int blen = put_attr(bpf, 0, TCA_KIND, "bpf", 4);
    unsigned char opts[400];
    char name[256];
    memset(name, 0, sizeof name);
    strcpy(name, "gex_test:[*fsobj]");
    uint32_t direct = TCA_BPF_FLAG_ACT_DIRECT;
    int olen = put_attr(opts, 0, TCA_BPF_FD, &prog, 4);
    olen = put_attr(opts, olen, TCA_BPF_NAME, name, sizeof name);
    olen = put_attr(opts, olen, TCA_BPF_FLAGS, &direct, 4);
    int full = put_attr(bpf, blen, TCA_OPTIONS | NLA_F_NESTED, opts, olen);
    want("delete a filter from an empty clsact", ask(RTM_DELTFILTER, 0, ifindex, 0, IN, info, NULL, 0), -ENOENT);
    want("an empty chain asked for", ask(RTM_GETTFILTER, 0, ifindex, 1, IN, info, NULL, 0), -EINVAL);
    drain();
    want("add a classifier", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, info, bpf, full), 0);
    want("its notification", notified(ifindex, &fl), RTM_NEWTFILTER);
    want("its flags", fl, NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
    want("dumped: a header and the program", dump(RTM_GETTFILTER, ifindex, IN), 2);
    struct nlmsghdr *second = (struct nlmsghdr *)(rbuf + NLMSG_ALIGN(((struct nlmsghdr *)rbuf)->nlmsg_len));
    want("the header's handle", ((struct tcmsg *)NLMSG_DATA((struct nlmsghdr *)rbuf))->tcm_handle, 0);
    want("the program's handle", ((struct tcmsg *)NLMSG_DATA(second))->tcm_handle, 1);
    want("its info", ((struct tcmsg *)NLMSG_DATA(second))->tcm_info, info);
    struct nlattr *id = find(second, TCA_BPF_ID, TCA_OPTIONS);
    want("its id", id ? *(uint32_t *)(id + 1) : 0, prog_id(prog));
    struct nlattr *gen = find(second, TCA_BPF_FLAGS_GEN, TCA_OPTIONS);
    want("its FLAGS_GEN", gen ? *(uint32_t *)(gen + 1) : 0, TCA_CLS_FLAGS_NOT_IN_HW);
    struct nlattr *nm = find(second, TCA_BPF_NAME, TCA_OPTIONS);
    want("its name", nm && !strcmp((char *)(nm + 1), name), 1);
    want("asked for", ask(RTM_GETTFILTER, 0, ifindex, 1, IN, info, NULL, 0), 0);
    want("the answer", rlen > 0 && ((struct nlmsghdr *)rbuf)->nlmsg_type == RTM_NEWTFILTER, 1);
    want("handle 0 asked for", ask(RTM_GETTFILTER, 0, ifindex, 0, IN, info, NULL, 0), -ENOENT);
    want("the same again", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, info, bpf, full), 0);
    want("now two programs and a header", dump(RTM_GETTFILTER, ifindex, IN), 3);
    want("newest first", ((struct tcmsg *)NLMSG_DATA((struct nlmsghdr *)(rbuf + NLMSG_ALIGN(((struct nlmsghdr *)rbuf)->nlmsg_len))))->tcm_handle, 2);
    want("another protocol at the priority", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, (17 << 16) | htons(ETH_P_IP), bpf, full), -EINVAL);

    unsigned char bad[512];
    int bl = put_attr(bad, 0, TCA_KIND, "bpf", 4);
    unsigned char bo[64];
    int bol = put_attr(bo, 0, TCA_BPF_FD, &sock_prog, 4);
    int badlen = put_attr(bad, bl, TCA_OPTIONS | NLA_F_NESTED, bo, bol);
    const uint32_t info2 = (18 << 16) | htons(ETH_P_ALL);
    want("a socket filter program", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, info2, bad, badlen), -EINVAL);
    int closed = 1000;
    bol = put_attr(bo, 0, TCA_BPF_FD, &closed, 4);
    badlen = put_attr(bad, bl, TCA_OPTIONS | NLA_F_NESTED, bo, bol);
    want("a descriptor not open", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, info2, bad, badlen), -EBADF);
    uint32_t two = 2;
    bol = put_attr(bo, 0, TCA_BPF_FD, &prog, 4);
    bol = put_attr(bo, bol, TCA_BPF_FLAGS, &two, 4);
    badlen = put_attr(bad, bl, TCA_OPTIONS | NLA_F_NESTED, bo, bol);
    want("an unknown flag", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, info2, bad, badlen), -EINVAL);
    want("no protocol", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, 18 << 16, bpf, full), -EINVAL);
    unsigned char nk[16];
    int nkl = put_attr(nk, 0, TCA_KIND, "nosuchcls", 10);
    want("an unknown classifier", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, info2, nk, nkl), -ENOENT);
    want("clsact's other minor", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, TC_H_CLSACT, info2, bpf, full), -ENOENT);
    want("no options", ask(RTM_NEWTFILTER, NLM_F_EXCL | NLM_F_CREATE, ifindex, 0, IN, info2, bpf, blen), -EINVAL);
    want("nothing left of those", dump(RTM_GETTFILTER, ifindex, IN), 3);

    drain();
    want("delete by priority", ask(RTM_DELTFILTER, 0, ifindex, 0, IN, info, NULL, 0), 0);
    want("its notification", notified(ifindex, &fl), RTM_DELTFILTER);
    want("deleted again", ask(RTM_DELTFILTER, 0, ifindex, 0, IN, info, NULL, 0), -ENOENT);
    want("none left", dump(RTM_GETTFILTER, ifindex, IN), 0);

    drain();
    want("delete clsact", ask(RTM_DELQDISC, 0, ifindex, H, TC_H_CLSACT, 0, kind, klen), 0);
    want("its notification", notified(ifindex, &fl), RTM_DELQDISC);
    want("delete it again", ask(RTM_DELQDISC, 0, ifindex, H, TC_H_CLSACT, 0, kind, klen), -EINVAL);
    want("a filter without clsact", ask(RTM_DELTFILTER, 0, ifindex, 0, IN, info, NULL, 0), -EINVAL);
    want("no CREATE", ask(RTM_NEWQDISC, 0, ifindex, H, TC_H_CLSACT, 0, kind, klen), -ENOENT);
    close(tun);
    umount(dir);
    rmdir(dir);
    close(prog);
    if (sock_prog >= 0) close(sock_prog);
    if (!failed) printf("tc ok\n");
    return failed;
}
