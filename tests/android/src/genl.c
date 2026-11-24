// Generic netlink's controller, as Android's Nl80211Proxy and libnl's
// genl_ctrl_resolve ask it: a NETLINK_GENERIC socket, CTRL_CMD_GETFAMILY
// for nlctrl by name and by id (NEWFAMILY: its id, version 2, header 0,
// maxattr 0, its two commands with their flags, its "notify" group at
// GENL_ID_CTRL), a family no kernel has (ENOENT), the request's checks
// (no attribute EINVAL, a short id ERANGE, an unterminated name EINVAL, a
// command it has not EOPNOTSUPP, an unknown family id ENOENT), and a dump
// that has nlctrl in it. Linux 7.0 has more families than this kernel, so
// only what holds for both is asked.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failed;

static void want(const char *what, long got, long expect) {
    if (got != expect) {
        printf("genl: %s: want %ld, got %ld\n", what, expect, got);
        failed = 1;
    }
}

static unsigned char buf[16384];

// A request to nlctrl with one attribute (or none), and the first answer.
static long ask(int fd, uint16_t family, uint8_t cmd, uint16_t flags, uint16_t type, const void *data, int len) {
    unsigned char req[256];
    memset(req, 0, sizeof req);
    struct nlmsghdr *h = (struct nlmsghdr *)req;
    struct genlmsghdr *g = (struct genlmsghdr *)(h + 1);
    int at = NLMSG_HDRLEN + GENL_HDRLEN;
    if (type) {
        struct nlattr *a = (struct nlattr *)(req + at);
        a->nla_len = NLA_HDRLEN + len;
        a->nla_type = type;
        memcpy(a + 1, data, len);
        at += NLA_ALIGN(a->nla_len);
    }
    h->nlmsg_len = at;
    h->nlmsg_type = family;
    h->nlmsg_flags = NLM_F_REQUEST | flags;
    h->nlmsg_seq = 9;
    g->cmd = cmd;
    g->version = 1;
    if (send(fd, req, at, 0) != at) return -errno;
    long n = recv(fd, buf, sizeof buf, 0);
    if (n < 0) return -errno;
    h = (struct nlmsghdr *)buf;
    if (h->nlmsg_type == NLMSG_ERROR) return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
    return n;
}

// The attribute of a type in a NEWFAMILY message, or NULL.
static struct nlattr *find(struct nlmsghdr *h, uint16_t type) {
    unsigned char *p = (unsigned char *)NLMSG_DATA(h) + GENL_HDRLEN, *end = (unsigned char *)h + h->nlmsg_len;
    while (p + NLA_HDRLEN <= end) {
        struct nlattr *a = (struct nlattr *)p;
        if (a->nla_len < NLA_HDRLEN) break;
        if ((a->nla_type & NLA_TYPE_MASK) == type) return a;
        p += NLA_ALIGN(a->nla_len);
    }
    return NULL;
}

static uint32_t u32_of(struct nlattr *a) { uint32_t v = 0; if (a) memcpy(&v, a + 1, a->nla_len >= 8 ? 4 : 2); return v; }

static void check_family(const char *what, long n) {
    if (n <= 0) {
        printf("genl: %s: %ld\n", what, n);
        failed = 1;
        return;
    }
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    struct genlmsghdr *g = NLMSG_DATA(h);
    want("NEWFAMILY's type", h->nlmsg_type, GENL_ID_CTRL);
    want("NEWFAMILY", g->cmd, CTRL_CMD_NEWFAMILY);
    want("its version", g->version, 2);
    struct nlattr *name = find(h, CTRL_ATTR_FAMILY_NAME);
    if (!name || strcmp((char *)(name + 1), "nlctrl")) {
        printf("genl: %s: name\n", what);
        failed = 1;
    }
    want("its id", u32_of(find(h, CTRL_ATTR_FAMILY_ID)) & 0xffff, GENL_ID_CTRL);
    want("its version attribute", u32_of(find(h, CTRL_ATTR_VERSION)), 2);
    want("its header", u32_of(find(h, CTRL_ATTR_HDRSIZE)), 0);
    want("its maxattr", u32_of(find(h, CTRL_ATTR_MAXATTR)), 0);
    // Ops: [1] GETFAMILY do+dump+policy, [2] GETPOLICY dump+policy.
    struct nlattr *ops = find(h, CTRL_ATTR_OPS);
    uint32_t seen[2][2] = {{0}};
    int k = 0;
    if (ops) {
        unsigned char *p = (unsigned char *)(ops + 1), *end = (unsigned char *)ops + ops->nla_len;
        while (p + NLA_HDRLEN <= end && k < 2) {
            struct nlattr *op = (struct nlattr *)p;
            unsigned char *q = (unsigned char *)(op + 1), *qe = p + op->nla_len;
            while (q + NLA_HDRLEN <= qe) {
                struct nlattr *f = (struct nlattr *)q;
                if (f->nla_type == CTRL_ATTR_OP_ID) memcpy(&seen[k][0], f + 1, 4);
                if (f->nla_type == CTRL_ATTR_OP_FLAGS) memcpy(&seen[k][1], f + 1, 4);
                q += NLA_ALIGN(f->nla_len);
            }
            k++;
            p += NLA_ALIGN(op->nla_len);
        }
    }
    want("ops", k, 2);
    want("op 1", seen[0][0], CTRL_CMD_GETFAMILY);
    want("op 1's flags", seen[0][1], GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP | GENL_CMD_CAP_HASPOL);
    want("op 2", seen[1][0], CTRL_CMD_GETPOLICY);
    want("op 2's flags", seen[1][1], GENL_CMD_CAP_DUMP | GENL_CMD_CAP_HASPOL);
    struct nlattr *grps = find(h, CTRL_ATTR_MCAST_GROUPS);
    if (!grps || !memmem(grps, grps->nla_len, "notify", 7)) {
        printf("genl: %s: no notify group\n", what);
        failed = 1;
    }
}

int main(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) {
        printf("genl: socket: %d\n", errno);
        return 1;
    }
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    want("bind", bind(fd, (struct sockaddr *)&sa, sizeof sa), 0);

    check_family("by name", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, CTRL_ATTR_FAMILY_NAME, "nlctrl", 7));
    uint16_t id = GENL_ID_CTRL;
    check_family("by id", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, CTRL_ATTR_FAMILY_ID, &id, 2));
    want("a family no kernel has", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, CTRL_ATTR_FAMILY_NAME, "gexnofamily", 12), -ENOENT);
    want("no attribute", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, 0, NULL, 0), -EINVAL);
    want("a short id", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, CTRL_ATTR_FAMILY_ID, &id, 1), -ERANGE);
    want("an unterminated name", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, CTRL_ATTR_FAMILY_NAME, "nlctrl", 6), -EINVAL);
    want("a long name", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, CTRL_ATTR_FAMILY_NAME, "abc\0xxxxxxxxxxxxx", 17), -ERANGE);
    want("a command it has not", ask(fd, GENL_ID_CTRL, CTRL_CMD_GETOPS, 0, 0, NULL, 0), -EOPNOTSUPP);
    want("no such family id", ask(fd, 0x7ff0, 1, 0, 0, NULL, 0), -ENOENT);

    // A dump: messages until DONE, nlctrl among them.
    long n = ask(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, NLM_F_DUMP, 0, NULL, 0);
    int found = 0, done = 0;
    for (int guard = 0; n > 0 && guard < 64 && !done; guard++) {
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            want("dump flags", h->nlmsg_flags & NLM_F_MULTI, NLM_F_MULTI);
            struct nlattr *name = find(h, CTRL_ATTR_FAMILY_NAME);
            if (name && !strcmp((char *)(name + 1), "nlctrl")) found = 1;
        }
        if (!done) n = recv(fd, buf, sizeof buf, 0);
    }
    want("the dump ends", done, 1);
    want("the dump has nlctrl", found, 1);
    close(fd);
    if (!failed) printf("genl ok\n");
    return failed;
}
