// Multicast memberships on internet sockets, as Linux keeps and checks
// them (net/ipv4/igmp.c, net/ipv6/mcast.c): the forms of the request, the
// group, the interface by index or by address, duplicates, a socket's
// limit, leaving what was not joined, and a stream socket refused. An
// interface below IPv6's minimum MTU has no IPv6 state to join on (a TUN
// device made here, as Android's Thread network service makes one and
// joins groups on it). Run as root (the TUN device).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int failed;

static void want(const char *what, int r, int err) {
    int got = r == 0 ? 0 : errno;
    if (got != err) {
        printf("mcast: %s: want %d, got %d\n", what, err, got);
        failed = 1;
    }
}

static int join6(int s, int name, const char *group, int ifindex, int family, socklen_t len) {
    struct group_req g;
    memset(&g, 0, sizeof g);
    g.gr_interface = ifindex;
    struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&g.gr_group;
    sa->sin6_family = family;
    inet_pton(AF_INET6, group, &sa->sin6_addr);
    return setsockopt(s, IPPROTO_IPV6, name, &g, len);
}

static int mreq6(int s, int name, const char *group, int ifindex) {
    struct ipv6_mreq m;
    inet_pton(AF_INET6, group, &m.ipv6mr_multiaddr);
    m.ipv6mr_interface = ifindex;
    return setsockopt(s, IPPROTO_IPV6, name, &m, sizeof m);
}

static int mreq4(int s, int name, const char *group, const char *local, int ifindex, socklen_t len) {
    struct ip_mreqn m;
    memset(&m, 0, sizeof m);
    inet_pton(AF_INET, group, &m.imr_multiaddr);
    if (local) inet_pton(AF_INET, local, &m.imr_address);
    m.imr_ifindex = ifindex;
    return setsockopt(s, IPPROTO_IP, name, &m, len);
}

int main(void) {
    int lo = if_nametoindex("lo");
    int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
    int s4 = socket(AF_INET, SOCK_DGRAM, 0);
    int t6 = socket(AF_INET6, SOCK_STREAM, 0);
    int t4 = socket(AF_INET, SOCK_STREAM, 0);
    if (lo <= 0 || s6 < 0 || s4 < 0 || t6 < 0 || t4 < 0) {
        printf("mcast: setup failed (errno %d)\n", errno);
        return 1;
    }

    // IPv6.
    want("join", join6(s6, MCAST_JOIN_GROUP, "ff02::1:2", lo, AF_INET6, sizeof(struct group_req)), 0);
    want("join again", join6(s6, MCAST_JOIN_GROUP, "ff02::1:2", lo, AF_INET6, sizeof(struct group_req)), EADDRINUSE);
    want("join again on any interface", join6(s6, MCAST_JOIN_GROUP, "ff02::1:2", 0, AF_INET6, sizeof(struct group_req)), EADDRINUSE);
    want("join a group that is not one", join6(s6, MCAST_JOIN_GROUP, "fe80::1", lo, AF_INET6, sizeof(struct group_req)), EINVAL);
    want("join an IPv4 family", join6(s6, MCAST_JOIN_GROUP, "ff02::1:3", lo, AF_INET, sizeof(struct group_req)), EADDRNOTAVAIL);
    want("join short", join6(s6, MCAST_JOIN_GROUP, "ff02::1:3", lo, AF_INET6, sizeof(struct group_req) - 1), EINVAL);
    want("join on no interface", join6(s6, MCAST_JOIN_GROUP, "ff02::1:3", 9999, AF_INET6, sizeof(struct group_req)), ENODEV);
    want("ipv6_mreq join", mreq6(s6, IPV6_ADD_MEMBERSHIP, "ff02::1:4", lo), 0);
    want("ipv6_mreq join again", mreq6(s6, IPV6_ADD_MEMBERSHIP, "ff02::1:4", lo), EADDRINUSE);
    want("ipv6_mreq on a stream socket", mreq6(t6, IPV6_ADD_MEMBERSHIP, "ff02::1:4", lo), EPROTO);
    want("leave", join6(s6, MCAST_LEAVE_GROUP, "ff02::1:2", lo, AF_INET6, sizeof(struct group_req)), 0);
    want("leave again", join6(s6, MCAST_LEAVE_GROUP, "ff02::1:2", lo, AF_INET6, sizeof(struct group_req)), EADDRNOTAVAIL);
    want("ipv6_mreq leave on any interface", mreq6(s6, IPV6_DROP_MEMBERSHIP, "ff02::1:4", 0), 0);
    want("leave a group that is not one", mreq6(s6, IPV6_DROP_MEMBERSHIP, "fe80::1", lo), EINVAL);
    want("an IPv6 membership on an IPv4 socket", mreq6(s4, IPV6_ADD_MEMBERSHIP, "ff02::1:4", lo), ENOPROTOOPT);

    // IPv4.
    want("ip_mreqn join", mreq4(s4, IP_ADD_MEMBERSHIP, "239.1.2.3", NULL, lo, sizeof(struct ip_mreqn)), 0);
    want("ip_mreqn join again", mreq4(s4, IP_ADD_MEMBERSHIP, "239.1.2.3", NULL, lo, sizeof(struct ip_mreqn)), EADDRINUSE);
    want("ip_mreq join by address", mreq4(s4, IP_ADD_MEMBERSHIP, "239.1.2.4", "127.0.0.1", 0, sizeof(struct ip_mreq)), 0);
    want("ip_mreq join by an address not here", mreq4(s4, IP_ADD_MEMBERSHIP, "239.1.2.5", "192.0.2.77", 0, sizeof(struct ip_mreq)), ENODEV);
    want("join a group that is not one", mreq4(s4, IP_ADD_MEMBERSHIP, "10.1.2.3", NULL, lo, sizeof(struct ip_mreqn)), EINVAL);
    want("join short", mreq4(s4, IP_ADD_MEMBERSHIP, "239.1.2.6", NULL, lo, 7), EINVAL);
    want("join on no interface", mreq4(s4, IP_ADD_MEMBERSHIP, "239.1.2.6", NULL, 9999, sizeof(struct ip_mreqn)), ENODEV);
    want("a membership on a stream socket", mreq4(t4, IP_ADD_MEMBERSHIP, "239.1.2.6", NULL, lo, sizeof(struct ip_mreqn)), EPROTO);
    char g[32];
    for (int i = 0; i < 18; i++) {
        snprintf(g, sizeof g, "239.2.0.%d", i);
        want("one of twenty", mreq4(s4, IP_ADD_MEMBERSHIP, g, NULL, lo, sizeof(struct ip_mreqn)), 0);
    }
    want("the twenty-first", mreq4(s4, IP_ADD_MEMBERSHIP, "239.2.1.0", NULL, lo, sizeof(struct ip_mreqn)), ENOBUFS);
    want("leave", mreq4(s4, IP_DROP_MEMBERSHIP, "239.1.2.3", NULL, lo, sizeof(struct ip_mreqn)), 0);
    want("leave again", mreq4(s4, IP_DROP_MEMBERSHIP, "239.1.2.3", NULL, lo, sizeof(struct ip_mreqn)), EADDRNOTAVAIL);
    struct group_req gr;
    memset(&gr, 0, sizeof gr);
    gr.gr_interface = lo;
    ((struct sockaddr_in6 *)&gr.gr_group)->sin6_family = AF_INET6;
    want("a group_req of IPv6 on an IPv4 socket", setsockopt(s4, IPPROTO_IP, MCAST_JOIN_GROUP, &gr, sizeof gr), EINVAL);

    // A TUN device: IPv6 state with its MTU at 1280 or more.
    char dir[] = "/tmp/mcast-XXXXXX";
    char node[64];
    if (!mkdtemp(dir) || mount("tmpfs", dir, "tmpfs", 0, NULL)) {
        printf("mcast: tmpfs (errno %d)\n", errno);
        return 1;
    }
    snprintf(node, sizeof node, "%s/tun", dir);
    if (mknod(node, S_IFCHR | 0600, makedev(10, 200))) {
        printf("mcast: mknod (errno %d)\n", errno);
        return 1;
    }
    int tun = open(node, O_RDWR);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "gexmc0");
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (tun < 0 || ioctl(tun, TUNSETIFF, &ifr)) {
        printf("mcast: TUNSETIFF (errno %d)\n", errno);
        return 1;
    }
    int ti = if_nametoindex("gexmc0");
    want("join on a TUN device that is down", join6(s6, MCAST_JOIN_GROUP, "ff02::fb", ti, AF_INET6, sizeof(struct group_req)), 0);
    ifr.ifr_mtu = 1279;
    if (ioctl(s6, SIOCSIFMTU, &ifr)) {
        printf("mcast: SIOCSIFMTU (errno %d)\n", errno);
        return 1;
    }
    want("join below IPv6's MTU", join6(s6, MCAST_JOIN_GROUP, "ff02::fc", ti, AF_INET6, sizeof(struct group_req)), EINVAL);
    // IPv4 state it has still: the socket's twentieth group.
    want("an IPv4 join there", mreq4(s4, IP_ADD_MEMBERSHIP, "239.3.0.1", NULL, ti, sizeof(struct ip_mreqn)), 0);
    ifr.ifr_mtu = 1280;
    if (ioctl(s6, SIOCSIFMTU, &ifr)) {
        printf("mcast: SIOCSIFMTU (errno %d)\n", errno);
        return 1;
    }
    want("join at IPv6's MTU again", join6(s6, MCAST_JOIN_GROUP, "ff02::fc", ti, AF_INET6, sizeof(struct group_req)), 0);
    close(tun);
    want("leave once the device is gone", join6(s6, MCAST_LEAVE_GROUP, "ff02::fb", ti, AF_INET6, sizeof(struct group_req)), 0);
    umount(dir);
    rmdir(dir);
    if (failed) return 1;
    printf("mcast ok\n");
    return 0;
}
