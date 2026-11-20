// A TCP listener reached from outside the guest: natively a program on the
// host connects to it on the loopback, and under gex the host forwards a
// port of its own to it (GEX_HOST_FORWARD), as the emulator forwards one to
// the guest's adbd. It listens as adbd does (IPv6, both stacks, any
// address) on the port given, says so, takes one connection, which comes
// from the IPv4 loopback, echoes it back in upper case until end of file,
// and says how much it echoed. run.sh is the other end.
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void die(const char *what) {
    printf("fwdecho: %s (errno %d)\n", what, errno);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) die("a port to listen on");
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s < 0) die("socket");
    int one = 1, zero = 0;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one)) die("SO_REUSEADDR");
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero)) die("IPV6_V6ONLY");
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(atoi(argv[1]));
    a.sin6_addr = in6addr_any;
    if (bind(s, (struct sockaddr *)&a, sizeof a)) die("bind");
    if (listen(s, 4)) die("listen");
    printf("listening\n");
    fflush(stdout);

    struct sockaddr_in6 peer;
    socklen_t len = sizeof peer;
    int c = accept(s, (struct sockaddr *)&peer, &len);
    if (c < 0) die("accept");
    static const unsigned char loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1};
    if (len != sizeof peer || peer.sin6_family != AF_INET6 || memcmp(&peer.sin6_addr, loopback, 16) || ntohs(peer.sin6_port) == 0) die("the peer is not the IPv4 loopback");

    char buf[4096];
    long total = 0;
    ssize_t n;
    while ((n = read(c, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) buf[i] = toupper((unsigned char)buf[i]);
        for (ssize_t done = 0; done < n;) {
            ssize_t w = write(c, buf + done, n - done);
            if (w <= 0) die("write");
            done += w;
        }
        total += n;
    }
    if (n < 0) die("read");
    close(c);
    close(s);
    printf("fwdecho ok %ld\n", total);
    return 0;
}
