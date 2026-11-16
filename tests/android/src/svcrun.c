// One program run as init runs a service: with the sockets its .rc file
// asks init for, made as init makes them, and their descriptors named in
// its environment. For trying one of Android's daemons against the
// kernel in seconds, where a boot takes minutes to reach it.
//
//   svcrun [name:type...] -- program [arguments...]
//
// A socket is written as its .rc line has it: "lmkd:seqpacket+passcred",
// "logdr:seqpacket", "logdw:dgram+passcred", "logd:stream"; "+listen"
// has init listen on it. Each is made in /dev/socket (CreateSocket,
// init/util.cpp): closed at an exec, SO_PASSCRED if asked, bound with the
// whole sockaddr_un, then given back to the exec and named
// ANDROID_SOCKET_<name> in the environment (Descriptor::Publish).
//
// Before that it leaves /dev as first-stage init and init.rc do, as far as
// a daemon needs it: a tmpfs with the kernel log, null, zero, the random
// devices and ptmx by number, socket/, and binder's three names linked
// into binderfs. Whoever runs it has proc mounted.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(x) \
    if ((x) != 0) { \
        printf("svcrun: %s: errno %d\n", #x, errno); \
        return 1; \
    }

int main(int argc, char **argv) {
    int split = 1;
    while (split < argc && strcmp(argv[split], "--")) split++;
    if (split + 1 >= argc) {
        printf("usage: svcrun [name:type[+passcred][+listen]...] -- program [arguments...]\n");
        return 2;
    }
    CHECK(mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755"));
    CHECK(mkdir("/dev/socket", 0755));
    CHECK(mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11)));
    CHECK(mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3)));
    CHECK(mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5)));
    CHECK(mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8)));
    CHECK(mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)));
    CHECK(mknod("/dev/ptmx", S_IFCHR | 0666, makedev(5, 2)));
    CHECK(symlink("/dev/binderfs/binder", "/dev/binder"));
    CHECK(symlink("/dev/binderfs/hwbinder", "/dev/hwbinder"));
    CHECK(symlink("/dev/binderfs/vndbinder", "/dev/vndbinder"));

    for (int i = 1; i < split; i++) {
        char name[64], kind[64];
        if (sscanf(argv[i], "%63[^:]:%63s", name, kind) != 2) {
            printf("svcrun: %s is not name:type\n", argv[i]);
            return 2;
        }
        int type = !strncmp(kind, "stream", 6) ? SOCK_STREAM : !strncmp(kind, "dgram", 5) ? SOCK_DGRAM : !strncmp(kind, "seqpacket", 9) ? SOCK_SEQPACKET : -1;
        if (type < 0) {
            printf("svcrun: %s is no kind of socket\n", kind);
            return 2;
        }
        int fd = socket(PF_UNIX, type | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            printf("svcrun: socket for %s: errno %d\n", name, errno);
            return 1;
        }
        struct sockaddr_un addr = {.sun_family = AF_UNIX};
        snprintf(addr.sun_path, sizeof addr.sun_path, "/dev/socket/%s", name);
        int on = 1;
        if (strstr(kind, "+passcred")) CHECK(setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof on));
        CHECK(bind(fd, (struct sockaddr *)&addr, sizeof addr));
        CHECK(fchmodat(AT_FDCWD, addr.sun_path, 0666, AT_SYMLINK_NOFOLLOW));
        if (strstr(kind, "+listen")) CHECK(listen(fd, 1 << 30));
        // The child's part: open across the exec, and named.
        CHECK(fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) & ~FD_CLOEXEC));
        char key[96], value[16];
        snprintf(key, sizeof key, "ANDROID_SOCKET_%s", name);
        for (char *c = key; *c; c++)
            if (!((*c >= '0' && *c <= '9') || (*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z'))) *c = '_';
        snprintf(value, sizeof value, "%d", fd);
        setenv(key, value, 1);
    }
    setenv("PATH", "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin", 1);
    execv(argv[split + 1], argv + split + 1);
    printf("svcrun: execv %s: errno %d\n", argv[split + 1], errno);
    return 1;
}
