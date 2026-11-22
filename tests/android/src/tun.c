// TUN devices (drivers/net/tun.c), as Android's Thread network service
// makes one: /dev/net/tun (misc 10:200), TUNSETIFF with IFF_TUN|IFF_NO_PI|
// IFF_TUN_EXCL, the MTU and flags set through an AF_INET6 datagram socket,
// the interface found by name. And what that changes elsewhere: the link
// messages a NETLINK_ROUTE listener of RTNLGRP_LINK gets as the device
// comes, changes and goes; its sysfs directory; and what the descriptor's
// reads, writes and polls do with no packet ever routed to it. A
// persistent device outlives its descriptor. Run as root (CAP_NET_ADMIN;
// it makes its node in a tmpfs, and mounts a sysfs, of its own).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define NAME "gextun0"

static void die(const char *what, long got) {
    printf("tun: %s (got %ld, errno %d)\n", what, got, errno);
    exit(1);
}

static void want_err(const char *what, long r, int err) {
    if (r != -1 || errno != err) {
        printf("tun: %s: want errno %d, got %ld (errno %d)\n", what, err, r, errno);
        exit(1);
    }
}

static char sys[] = "/tmp/tun-sys-XXXXXX";
static char dir[] = "/tmp/tun-dev-XXXXXX";
static char node[PATH_MAX];

static int open_tun(void) {
    int fd = open(node, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) die("open the node", fd);
    return fd;
}

static void slurp(const char *rel, char *buf, size_t n) {
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", sys, rel);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("tun: cannot open %s (errno %d)\n", rel, errno);
        exit(1);
    }
    ssize_t r = read(fd, buf, n - 1);
    if (r < 0) {
        printf("tun: cannot read %s (errno %d)\n", rel, errno);
        exit(1);
    }
    buf[r] = 0;
    close(fd);
}

static void want_file(const char *rel, const char *want) {
    char buf[256];
    slurp(rel, buf, sizeof buf);
    if (strcmp(buf, want)) {
        printf("tun: %s is \"%s\", not \"%s\"\n", rel, buf, want);
        exit(1);
    }
}

// The listener, bound to RTNLGRP_LINK.
static int listener;

// The next link message about interface `index`, waiting up to a second:
// its type, change mask, flags and MTU (-1 without one). 0 when none came.
static int next_link(int index, unsigned *change, unsigned *flags, int *mtu, char *kind) {
    static char buf[16384];
    static int len, at;
    for (;;) {
        while (at < len) {
            struct nlmsghdr *h = (struct nlmsghdr *)(buf + at);
            if (!NLMSG_OK(h, (unsigned)(len - at))) break;
            at += NLMSG_ALIGN(h->nlmsg_len);
            if (h->nlmsg_type != RTM_NEWLINK && h->nlmsg_type != RTM_DELLINK) continue;
            struct ifinfomsg *i = NLMSG_DATA(h);
            if (i->ifi_index != index) continue;
            *change = i->ifi_change;
            *flags = i->ifi_flags;
            *mtu = -1;
            if (kind) kind[0] = 0;
            int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof *i);
            for (struct rtattr *a = IFLA_RTA(i); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
                if (a->rta_type == IFLA_MTU) *mtu = *(int *)RTA_DATA(a);
                if (a->rta_type == IFLA_LINKINFO && kind) {
                    int ilen = RTA_PAYLOAD(a);
                    for (struct rtattr *b = RTA_DATA(a); RTA_OK(b, ilen); b = RTA_NEXT(b, ilen))
                        if (b->rta_type == IFLA_INFO_KIND) snprintf(kind, 16, "%s", (char *)RTA_DATA(b));
                }
            }
            return h->nlmsg_type;
        }
        struct pollfd p = {listener, POLLIN, 0};
        if (poll(&p, 1, 1000) != 1) return 0;
        len = recv(listener, buf, sizeof buf, 0);
        at = 0;
        if (len <= 0) die("receive from the route socket", len);
    }
}

static void want_link(const char *what, int index, int type, unsigned change, unsigned flags, int mtu) {
    unsigned c, f;
    int m;
    int t = next_link(index, &c, &f, &m, NULL);
    printf("%s: %s change %#x flags %#x mtu %d\n", what, t == RTM_NEWLINK ? "NEWLINK" : t == RTM_DELLINK ? "DELLINK" : "none", c, f, m);
    if (t != type || c != change || f != flags || (mtu >= 0 && m != mtu)) {
        printf("tun: %s: want %s change %#x flags %#x mtu %d\n", what, type == RTM_NEWLINK ? "NEWLINK" : "DELLINK", change, flags, mtu);
        exit(1);
    }
}

static int ifreq_ioctl(int s, unsigned long req, const char *name, struct ifreq *ifr) {
    memset(ifr, 0, sizeof *ifr);
    snprintf(ifr->ifr_name, IFNAMSIZ, "%s", name);
    return ioctl(s, req, ifr);
}

int main(void) {
    if (!mkdtemp(sys)) die("mkdtemp", 0);
    if (mount("sysfs", sys, "sysfs", 0, NULL)) die("mount sysfs", 0);
    if (!mkdtemp(dir)) die("mkdtemp", 0);
    if (mount("tmpfs", dir, "tmpfs", 0, NULL)) die("mount tmpfs", 0);
    snprintf(node, sizeof node, "%s/tun", dir);
    if (mknod(node, S_IFCHR | 0600, makedev(10, 200))) die("mknod", 0);

    // The misc device, named net/tun for its node.
    want_file("class/misc/tun/uevent", "MAJOR=10\nMINOR=200\nDEVNAME=net/tun\n");

    listener = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK};
    if (listener < 0 || bind(listener, (struct sockaddr *)&sa, sizeof sa)) die("route listener", listener);
    int s6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s6 < 0) die("inet6 socket", s6);

    // Before TUNSETIFF.
    int fd = open_tun();
    unsigned features = 0;
    if (ioctl(fd, TUNGETFEATURES, &features) || features != 0x7173) die("TUNGETFEATURES", features);
    struct ifreq ifr;
    want_err("TUNGETIFF unattached", ioctl(fd, TUNGETIFF, &ifr), EBADFD);
    want_err("an unknown ioctl unattached", ioctl(fd, _IO('T', 0xf0)), EBADFD);
    char c;
    want_err("a read unattached", read(fd, &c, 1), EBADFD);
    struct pollfd p = {fd, POLLIN | POLLOUT, 0};
    if (poll(&p, 1, 0) != 1 || p.revents != POLLERR) die("poll unattached is POLLERR alone", p.revents);
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_NO_PI;
    want_err("TUNSETIFF with no type", ioctl(fd, TUNSETIFF, &ifr), EINVAL);

    // Made, as the Thread service makes thread-wpan.
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, NAME);
    ifr.ifr_flags = (short)(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
    if (ioctl(fd, TUNSETIFF, &ifr)) die("TUNSETIFF", -1);
    if (strcmp(ifr.ifr_name, NAME) || (unsigned short)ifr.ifr_flags != (IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL)) die("the ifreq back", ifr.ifr_flags);
    int index = if_nametoindex(NAME);
    if (index <= 0) die("if_nametoindex", index);
    char kind[16];
    unsigned ch, fl;
    int mtu;
    int t = next_link(index, &ch, &fl, &mtu, kind);
    printf("registered: %s change %#x flags %#x mtu %d kind %s\n", t == RTM_NEWLINK ? "NEWLINK" : "none", ch, fl, mtu, kind);
    if (t != RTM_NEWLINK || ch != 0xffffffff || fl != 0x1090 || mtu != 1500 || strcmp(kind, "tun")) die("the link message at registration", t);
    want_err("a second TUNSETIFF", ioctl(fd, TUNSETIFF, &ifr), EEXIST);
    int fd2 = open_tun();
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, NAME);
    ifr.ifr_flags = (short)(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
    want_err("TUNSETIFF of a name there, exclusive", ioctl(fd2, TUNSETIFF, &ifr), EBUSY);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    want_err("a second queue of a single-queue device", ioctl(fd2, TUNSETIFF, &ifr), EBUSY);
    close(fd2);

    // What it is.
    if (ioctl(fd, TUNGETIFF, &ifr) || strcmp(ifr.ifr_name, NAME) || (unsigned short)ifr.ifr_flags != 0x1001) die("TUNGETIFF", (unsigned short)ifr.ifr_flags);
    if (ifreq_ioctl(s6, SIOCGIFFLAGS, NAME, &ifr) || (unsigned short)ifr.ifr_flags != 0x1090) die("SIOCGIFFLAGS made", (unsigned short)ifr.ifr_flags);
    if (ifreq_ioctl(s6, SIOCGIFMTU, NAME, &ifr) || ifr.ifr_mtu != 1500) die("SIOCGIFMTU", ifr.ifr_mtu);
    if (ifreq_ioctl(s6, SIOCGIFTXQLEN, NAME, &ifr) || ifr.ifr_qlen != 500) die("SIOCGIFTXQLEN", ifr.ifr_qlen);
    if (ifreq_ioctl(s6, SIOCGIFHWADDR, NAME, &ifr) || ifr.ifr_hwaddr.sa_family != 0xfffe) die("SIOCGIFHWADDR", ifr.ifr_hwaddr.sa_family);
    char path[PATH_MAX], buf[256];
    snprintf(path, sizeof path, "%s/class/net/" NAME, sys);
    char real[PATH_MAX], want[PATH_MAX];
    if (!realpath(path, real)) die("its class link", 0);
    snprintf(want, sizeof want, "%s/devices/virtual/net/" NAME, sys);
    if (strcmp(real, want)) die("not a virtual device", 0);
    want_file("class/net/" NAME "/type", "65534\n");
    want_file("class/net/" NAME "/flags", "0x1090\n");
    want_file("class/net/" NAME "/addr_len", "0\n");
    want_file("class/net/" NAME "/address", "\n");
    want_file("class/net/" NAME "/tx_queue_len", "500\n");
    want_file("class/net/" NAME "/operstate", "down\n");
    want_file("class/net/" NAME "/tun_flags", "0x1001\n");
    want_file("class/net/" NAME "/owner", "-1\n");
    want_file("class/net/" NAME "/group", "-1\n");
    snprintf(want, sizeof want, "INTERFACE=" NAME "\nIFINDEX=%d\n", index);
    want_file("class/net/" NAME "/uevent", want);
    snprintf(path, sizeof path, "%s/class/net/" NAME "/carrier", sys);
    int cfd = open(path, O_RDONLY);
    if (cfd < 0) die("open carrier", cfd);
    want_err("carrier while down", read(cfd, buf, sizeof buf), EINVAL);
    close(cfd);

    // Down: nothing to read, not writable, a packet refused.
    want_err("a read with nothing there", read(fd, buf, sizeof buf), EAGAIN);
    p.revents = 0;
    if (poll(&p, 1, 0) != 0) die("poll down", p.revents);
    want_err("a packet while down", write(fd, "\x60", 1), EIO);
    want_err("a packet of no IP version", write(fd, "\x10", 1), EINVAL);

    // Its MTU and flags, as the Thread service sets them.
    if (ifreq_ioctl(s6, SIOCGIFMTU, NAME, &ifr)) die("SIOCGIFMTU", -1);
    ifr.ifr_mtu = 67;
    want_err("an MTU below 68", ioctl(s6, SIOCSIFMTU, &ifr), EINVAL);
    ifr.ifr_mtu = 65536;
    want_err("an MTU above 65535", ioctl(s6, SIOCSIFMTU, &ifr), EINVAL);
    ifr.ifr_mtu = 1500;
    if (ioctl(s6, SIOCSIFMTU, &ifr)) die("SIOCSIFMTU the same", -1);
    ifr.ifr_mtu = 1280;
    if (ioctl(s6, SIOCSIFMTU, &ifr)) die("SIOCSIFMTU", -1);
    want_link("mtu", index, RTM_NEWLINK, 0, 0x1090, 1280);
    if (ifreq_ioctl(s6, SIOCGIFFLAGS, NAME, &ifr)) die("SIOCGIFFLAGS", -1);
    ifr.ifr_flags = IFF_UP | IFF_MULTICAST | IFF_NOARP;
    if (ioctl(s6, SIOCSIFFLAGS, &ifr)) die("SIOCSIFFLAGS up", -1);
    want_link("up", index, RTM_NEWLINK, IFF_UP, 0x110d1, 1280);
    if (ifreq_ioctl(s6, SIOCGIFFLAGS, NAME, &ifr) || (unsigned short)ifr.ifr_flags != 0x10d1) die("SIOCGIFFLAGS up", (unsigned short)ifr.ifr_flags);
    want_file("class/net/" NAME "/flags", "0x1091\n");
    want_file("class/net/" NAME "/operstate", "unknown\n");
    want_file("class/net/" NAME "/carrier", "1\n");
    want_file("class/net/" NAME "/mtu", "1280\n");

    // Up: writable, a packet taken whole; still nothing to read.
    p.revents = 0;
    if (poll(&p, 1, 0) != 1 || p.revents != POLLOUT) die("poll up is POLLOUT alone", p.revents);
    if (write(fd, "\x60", 1) != 1) die("a packet while up", -1);
    want_err("a read up with nothing there", read(fd, buf, sizeof buf), EAGAIN);

    // Down by flags 0: what a user may clear goes, POINTOPOINT stays.
    if (ifreq_ioctl(s6, SIOCGIFFLAGS, NAME, &ifr)) die("SIOCGIFFLAGS", -1);
    ifr.ifr_flags = 0;
    if (ioctl(s6, SIOCSIFFLAGS, &ifr)) die("SIOCSIFFLAGS 0", -1);
    want_link("down", index, RTM_NEWLINK, IFF_UP | IFF_MULTICAST | IFF_NOARP, IFF_POINTOPOINT, 1280);
    if (ifreq_ioctl(s6, SIOCGIFFLAGS, NAME, &ifr) || (unsigned short)ifr.ifr_flags != IFF_POINTOPOINT) die("SIOCGIFFLAGS 0", (unsigned short)ifr.ifr_flags);
    ifr.ifr_flags = IFF_UP | IFF_MULTICAST | IFF_NOARP;
    if (ioctl(s6, SIOCSIFFLAGS, &ifr)) die("SIOCSIFFLAGS up again", -1);
    want_link("up again", index, RTM_NEWLINK, IFF_UP | IFF_MULTICAST | IFF_NOARP, 0x110d1, 1280);

    // Closed: gone, said down and deleted.
    close(fd);
    want_link("closed", index, RTM_NEWLINK, IFF_UP | IFF_RUNNING, 0x1090, 1280);
    want_link("deleted", index, RTM_DELLINK, 0xffffffff, 0x1090, 1280);
    if (if_nametoindex(NAME) != 0) die("the name after close", 0);
    want_err("SIOCGIFFLAGS of it", ifreq_ioctl(s6, SIOCGIFFLAGS, NAME, &ifr), ENODEV);

    // A template, and a persistent device that outlives its descriptor.
    fd = open_tun();
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "gextun%d");
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr)) die("TUNSETIFF with a template", -1);
    if (strcmp(ifr.ifr_name, "gextun0")) die("the template's name", 0);
    index = if_nametoindex("gextun0");
    if (next_link(index, &ch, &fl, &mtu, NULL) != RTM_NEWLINK) die("registered again", 0);
    if (ioctl(fd, TUNSETPERSIST, 1)) die("TUNSETPERSIST", -1);
    if (ioctl(fd, TUNGETIFF, &ifr) || (unsigned short)ifr.ifr_flags != 0x1801) die("TUNGETIFF persistent", (unsigned short)ifr.ifr_flags);
    close(fd);
    if (if_nametoindex("gextun0") != (unsigned)index) die("the persistent device after close", 0);
    fd = open_tun();
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "gextun0");
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    want_err("attaching a TAP descriptor to a TUN device", ioctl(fd, TUNSETIFF, &ifr), EINVAL);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr)) die("attaching again", -1);
    if (ioctl(fd, TUNSETPERSIST, 0)) die("TUNSETPERSIST 0", -1);
    close(fd);
    for (int i = 0; i < 100 && if_nametoindex("gextun0"); i++) usleep(10000);
    if (if_nametoindex("gextun0") != 0) die("the device after its persistence went", 0);

    umount(dir);
    rmdir(dir);
    umount(sys);
    rmdir(sys);
    printf("tun ok\n");
    return 0;
}
