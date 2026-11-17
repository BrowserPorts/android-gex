// nfnetlink_log's configuration, as Android's netd sends it at its start
// (NFLogListener): a NETLINK_NETFILTER socket, the protocol unbind, then
// a log group bound and its copy mode set. Prints each request's answer
// (the acknowledgement's error) and checks them against Linux 7.0's. As
// root.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// What Linux 7.0 printed.
static const char expected[] =
    "sockets: 1 1\n"
    "timestamps: 0\n"
    "pf unbind: 0\n"
    "mode of a group never bound: -19\n"
    "unbind of a group never bound: -19\n"
    "bind: 0\n"
    "bind again: -16\n"
    "bind from another socket: -1\n"
    "mode from another socket: -1\n"
    "mode packet: 0\n"
    "mode 7: 0\n"
    "unbind: 0\n"
    "bind again after: 0\n"
    "bind from another after the first closed: 0\n";

static char out_buf[2048];
static size_t used;

static void SAY(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[256];
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fputs(line, stdout);
    if (n > 0 && used + (size_t)n < sizeof out_buf) {
        memcpy(out_buf + used, line, (size_t)n);
        used += (size_t)n;
    }
}

static int open_nf(void) {
    int s = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_NETFILTER);
    struct sockaddr_nl a = {.nl_family = AF_NETLINK};
    if (s >= 0)
        bind(s, (struct sockaddr *)&a, sizeof a);
    return s;
}

// A config request with ACK: one attribute (cmd, or mode). The answer's
// error (0 for done), or -1000 for no answer.
static int config(int s, uint16_t group, int cmd, int mode) {
    struct {
        struct nlmsghdr nh;
        struct nfgenmsg nf;
        struct nfattr attr;
        union {
            struct nfulnl_msg_config_cmd cmd;
            struct nfulnl_msg_config_mode mode;
        } u;
    } __attribute__((packed)) msg;
    memset(&msg, 0, sizeof msg);
    size_t payload = cmd >= 0 ? sizeof msg.u.cmd : sizeof msg.u.mode;
    msg.nh.nlmsg_len = NLMSG_HDRLEN + sizeof msg.nf + NFA_LENGTH(payload);
    msg.nh.nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
    msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nh.nlmsg_seq = 1;
    msg.nf.nfgen_family = AF_UNSPEC;
    msg.nf.version = NFNETLINK_V0;
    msg.nf.res_id = htons(group);
    msg.attr.nfa_len = NFA_LENGTH(payload);
    if (cmd >= 0) {
        msg.attr.nfa_type = NFULA_CFG_CMD;
        msg.u.cmd.command = (uint8_t)cmd;
    } else {
        msg.attr.nfa_type = NFULA_CFG_MODE;
        msg.u.mode.copy_mode = (uint8_t)mode;
        msg.u.mode.copy_range = htonl(0xffff);
    }
    struct sockaddr_nl k = {.nl_family = AF_NETLINK};
    if (sendto(s, &msg, msg.nh.nlmsg_len, 0, (struct sockaddr *)&k, sizeof k) < 0)
        return -errno;
    char buf[512];
    struct timeval tv = {2, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ssize_t n = recv(s, buf, sizeof buf, 0);
    if (n < (ssize_t)NLMSG_HDRLEN)
        return -1000;
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    if (h->nlmsg_type != NLMSG_ERROR)
        return -2000;
    return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
}

int main(void) {
    int a = open_nf(), b = open_nf();
    SAY("sockets: %d %d\n", a >= 0, b >= 0);
    int one = 1;
    SAY("timestamps: %d\n", setsockopt(a, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one));
    SAY("pf unbind: %d\n", config(a, 0, NFULNL_CFG_CMD_PF_UNBIND, 0));
    SAY("mode of a group never bound: %d\n", config(a, 5, -1, NFULNL_COPY_PACKET));
    SAY("unbind of a group never bound: %d\n", config(a, 5, NFULNL_CFG_CMD_UNBIND, 0));
    SAY("bind: %d\n", config(a, 5, NFULNL_CFG_CMD_BIND, 0));
    SAY("bind again: %d\n", config(a, 5, NFULNL_CFG_CMD_BIND, 0));
    SAY("bind from another socket: %d\n", config(b, 5, NFULNL_CFG_CMD_BIND, 0));
    SAY("mode from another socket: %d\n", config(b, 5, -1, NFULNL_COPY_META));
    SAY("mode packet: %d\n", config(a, 5, -1, NFULNL_COPY_PACKET));
    SAY("mode 7: %d\n", config(a, 5, -1, 7));
    SAY("unbind: %d\n", config(a, 5, NFULNL_CFG_CMD_UNBIND, 0));
    SAY("bind again after: %d\n", config(a, 5, NFULNL_CFG_CMD_BIND, 0));
    close(a);
    SAY("bind from another after the first closed: %d\n", config(b, 5, NFULNL_CFG_CMD_BIND, 0));
    if (expected[0] && strcmp(out_buf, expected) != 0) {
        printf("nflog: not what Linux shows\n");
        return 1;
    }
    printf(expected[0] ? "nflog ok\n" : "nflog done\n");
    return 0;
}
